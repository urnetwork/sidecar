// M1's gate (TEST-M1-11; §23.4's M1 exit, §23.6's M1 row, FS-54, FS-55, D-TEST-9, R-TEST-6): the first sweep,
// and the shape every later gate's gate_m<n>.go repeats. §23.6 names one schedule at M1, OPS's FS-54, and every
// Gn-out runs OPS's FS-55; neither is a schedule, so this sweep names their tests in place of the convention. The
// rest is §23.4's exit criteria and §23.6's closure, each with the tests the owning tasks wrote: no audit gates
// anything (R-TEST-6), so these local checks are the whole evidence a person reads at the review.
//
// Two exit criteria have production halves, stage 1 enforced and the daemon on darwin, linux and windows in
// preview_networks only, and they read open, never pass, whatever their local tests do. So does every item a
// person reviews. This file also keeps, until each later sweep's task moves them into its own file, the items
// OPS-M1-07's hand-written gates.yml held for later gates.

package fault

import (
	"time"
)

// FS-54's three build legs: the release leg, the tagged build and promotion (OPS-M1-01, OPS-M1-02).
var gateFs54Tests = []*GateTest{
	{Repo: "server", Package: ".", Names: []string{"TestSidecarPendingBuildTags", "TestReleaseBuildRegistersNoPendingGroup"}},
	{Repo: "server", Package: ".", Tags: "sidecar_pending", Stores: true, Names: []string{"TestSidecarGroupsEndTheMigrations", "TestSidecarGroupsAreAdditive", "TestSidecarGroupsApplyOnAPrivateDatabase"}},
	{Repo: "server", Package: "./local/sidecar-migrations", Names: []string{"TestPromoteMovesOnlyItsOwnGroup", "TestPromoteRefusesOutOfOrder", "TestPromoteResultCompilesOnBothLegs"}},
}

var gateM1Sweep = RegisterGateSweep(&GateSweep{
	Gate:  "M1",
	Cases: map[string][]*GateTest{"FS-54": gateFs54Tests},
	Items: []*GateItem{
		{
			Item: "stage 1 and D-TEAM-14 enforced (§23.4's M1 exit; TEAM-M1-01)",
			// api's tests read the keys test-env.sh provides, so each runs on the private stores, and its db half
			// reads MG0's tables, which only a sidecar_pending build registers
			Tests: []*GateTest{
				{Repo: "server", Package: "./api", Stores: true, Names: []string{"TestClientAdminRefusalIsEnforcedWhateverTheConfigSays", "TestEmbedRefusalIsNotCountedAsStageOne", "TestStrictExpTokenIsRefusedOnEveryPaymentRoute", "TestStrictExpGateRefusesWhateverTheConfigSays", "TestSidecarTokenRoutes"}},
				{Repo: "server", Package: "./api", Tags: "sidecar_pending", Stores: true, Names: []string{"TestMarkedClientTokensAreRefusedOnEveryAdminRoute", "TestClientWhoseMarksCannotBeReadIsRefusedOnEveryAdminRoute", "TestApiRefusesAnExpiredStrictExpToken"}},
			},
			External: "production: stage 1 enforced there after its 14 log-only days (D-PHASE-3), which no local run shows",
		},
		{
			Item: "Required RPC after §6.4's M1 identity check (§23.4's M1 exit; PROTO-M1-11)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{"TestSubprotocolRequiredRpcAfterTheIdentityCheck", "TestSubprotocolNothingBeforeAVerifiedHello", "TestSubprotocolNoSessionIsUnavailableEncryption", "TestSubprotocolControlContractCarriesNoData"}},
				{Repo: "server", Package: "./connect", Stores: true, Names: []string{"TestSidecarSubprotocolT3HelloHeadCheckAndSealedData"}},
			},
		},
		{
			Item: "push resyncs after a resident restart (§23.4's M1 exit; PROTO-M1-11)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{"TestPushResyncsAfterAResidentRestart", "TestPushPartialResetAppliesNothingUntilVersionsRefetched"}},
				{Repo: "server", Package: "./connect", Stores: true, Names: []string{"TestSidecarPushFromARealResidentKeptByTheDispatcher"}},
			},
		},
		{
			Item: "envelope fuzzed (§23.4's M1 exit), its seeds running as tests through §22.6's registry (TEST-M1-10)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: ".", Names: []string{"FuzzEnvelope", "FuzzChunkReassembly", "FuzzProtocolBody"}},
				{Repo: "sidecar", Package: "./protocol", Names: []string{"FuzzBody"}},
				{Repo: "sidecar", Package: "./check", Tags: "sidecar_check", Names: []string{"TestFuzzRegistry", "TestFuzzSeedsRunUnderTestSh"}},
			},
		},
		{
			Item: "daemon on darwin, linux and windows, in preview_networks only (§23.4's M1 exit; D-TRUST-3; CORE-M1-13)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: ".", Names: []string{"TestCoreM1GateRowsHaveTheirTests", "TestCoreM1GateEnrollsAndRefreshesEndToEnd", "TestOtherUidRefused", "TestPreviewRefusalSurfaces"}},
				{Repo: "server", Package: "./model", Names: []string{"TestSidecarPreviewAllowedOnlyForAListedNetwork", "TestSidecarPreviewRefusesWhenTheFileCannotBeRead"}},
			},
			External: "hardware and production: the daemon's hand runs on linux and windows hosts, since this host runs darwin and the legs runner only compiles windows, and preview_networks in production's config/<env>/sidecar.yml",
		},
		{
			Item: "typed signing (§23.6's M1 closure; PROTO-M1-01)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./protocol/bridge", Names: []string{"TestVerifySignedRefusesEveryOtherType", "TestVerifySignedRefusesRewrittenType", "TestVerifySignedChecksTypeBeforeSignature", "TestVerifySignedCoversReceivedBytesNeverAReMarshal", "FuzzSignedTypeConfusion"}},
			},
		},
		{
			Item: "the keystore result (§23.6's M1 closure; D-CORE-15; CORE-M1-02)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: ".", Names: []string{"TestAbsentWithNothingRecordedCreatesU", "TestAbsentWithRecordedIdCreatesNothing", "TestLockedCreatesNothing", "TestFailedCreatesNothing", "TestCorruptBytesAreFailed", "TestLostKeychainWrapIsKeystoreLost"}},
			},
		},
		{
			Item: "Q-TEST-6's descriptor lint: no oneof from the envelope, stream and push roots (§23.6's M1 closure)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./protocol", Names: []string{"TestNoOneofFromEnvelopeStreamAndPushRoots", "TestOneofLintCatchesPlantedDeclarations", "TestNoOneofInWhatStreamsAndPushesCarry"}},
			},
		},
		{
			Item: "make check's rules over this tree (§4.7), beside test.sh's module phases, which run first in its gate cadence",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./check", Tags: "sidecar_check", Names: []string{"TestDeps", "TestLayering", "TestLegs", "TestCgo", "TestHygiene", "TestEveryRowHasARuleAndAPlantedViolation"}},
			},
		},
		{
			Item: "§22.4's release fixture, from the consumer wiring (build's sidecar release step)",
			// its make check takes over an hour and grows with the tree, past the tool's default bound, so it runs
			// under the 3h run.sh's BUILD_TEST gives it (QD-1056, QD-1058)
			Tests: []*GateTest{
				{Repo: "build", Dir: "all", Package: ".", Tags: "sidecar_release_fixture", Timeout: 3 * time.Hour, Names: []string{"TestSidecarReleaseFixture"}},
			},
		},
	},
})

// M1's entry review reads its design closure, which a person signs.
var gateM1InSweep = RegisterGateSweep(&GateSweep{
	Gate: "M1-in",
	Items: []*GateItem{
		{
			Item:     "§23.6's M1 design closure: typed signing; transport-token states; the keystore result; HTTP liveness; persistent taint and bridge anchor (§5, §6, §7, §18); Q-CORE-4, Q-TEST-6",
			External: "people: the Gn-in review reads and signs the closure (§23.8)",
		},
	},
})

// FS-55 at every Gn-out (OPS-M1-07): server's binaries built at N and N+1 against main's schema.
var gateEverySweep = RegisterGateSweep(&GateSweep{
	Gate: "every",
	Cases: map[string][]*GateTest{
		"FS-55": {
			{Repo: "server", Package: "./local/fs55", Stores: true, Names: []string{"TestFs55OnServerBinaries"}, Args: []string{"-fs55.base={base}", "-fs55.group={group}"}},
		},
	},
})

// The items OPS-M1-07's hand-written gates.yml held for later gates, kept until TEST-M5-02 and TEST-M7-01 move each
// into its own sweep. M2's went into gate_m2_out.go (TEST-M2-19): the nvme run, and the 0x0010 interop artifact,
// which left the gate with MLS (owner decision 610); M3's into gate_m3.go (TEST-M3-02).
var (
	gateM5CarriedSweep = RegisterGateSweep(&GateSweep{
		Gate:  "M5",
		Items: []*GateItem{{Item: "S7's SNI-less abuse@<root> case"}},
	})
	gateM7CarriedSweep = RegisterGateSweep(&GateSweep{
		Gate:  "M7",
		Items: []*GateItem{{Item: "D-MAIL-9's census run, with §14's outbound probe", External: "production: the production edges"}},
	})
)
