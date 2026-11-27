//go:build !ios_extension && !sidecar_http && !js

// DESIGN-COMPUTE §2.4's compute invariants as data (CTRUST-M11-02, D-CTRUST-1), so each has a named proof and no later
// change drops one unseen. Each invariant carries its id, a line pointing at its §2.4 text, the areas §2.4's text names
// as enforcing it, and a row per enforcing point: its area, what it holds, where its tests live, the tests that prove
// it, the milestone whose exit brings them (§19.1) and the task that owns them.
//
// computeInvariantsLanded is the newest compute milestone whose exit has passed, raised by each milestone's gate sweep
// as testdata/metadata/fields.yml's landed is. A row at or before it must name tests that exist: the check parses its
// package's _test.go files with go/parser, building nothing and running nothing, and finds each as a top-level Test
// function, never a subtest or a method. A later row is logged as pending with its task. It names the tests its task's
// plan gives, and none where the plan describes them only in words (LSTN's and SAFE's), and the sweep that raises the
// mark corrects and fills them in as their tasks land. A row in the server or sdk repo is listed with its repo and not
// read here. A test file that does not parse fails the check, since a broken file proves nothing. Nothing here imports
// another area's package or runs its tests.
//
// §2.4 lists IC-1 to IC-24, IC-24 coming with the support skill (CO-45, CO-46), while D-CTRUST-1 and the plan still say
// IC-23: the matrix follows §2.4, which TestComputeInvariantsEachNamed reads. Where §2.4's text names support (IC-2,
// IC-12, IC-24), SUP is among the areas, its rows owned by the support-skill track, since §28 has no plan tasks.

package sidecar

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// A compute milestone's exit, in §19.1's row order, which is §19.3's build order. M12 and M13 come in two parts, each
// with its own exit, and part b of M12 follows M13's parts.
type computeMilestone int

const (
	// DESIGN.md's last milestone: no compute milestone's exit has passed
	computeMilestoneM10 computeMilestone = iota
	computeMilestoneM11
	computeMilestoneM12a
	computeMilestoneM13a
	computeMilestoneM13b
	computeMilestoneM12b
	computeMilestoneM14
	computeMilestoneM15
	computeMilestoneM16
)

// Each milestone's name, as §19.1 writes it.
var computeMilestoneNames = map[computeMilestone]string{
	computeMilestoneM10:  "M10",
	computeMilestoneM11:  "M11",
	computeMilestoneM12a: "M12a",
	computeMilestoneM13a: "M13a",
	computeMilestoneM13b: "M13b",
	computeMilestoneM12b: "M12b",
	computeMilestoneM14:  "M14",
	computeMilestoneM15:  "M15",
	computeMilestoneM16:  "M16",
}

// §19.1's name.
func (self computeMilestone) String() string {
	if name, ok := computeMilestoneNames[self]; ok {
		return name
	}
	return fmt.Sprintf("computeMilestone(%d)", int(self))
}

// The milestone's number, which a plan task's id carries: 12 for M12a and M12b.
func (self computeMilestone) number() int {
	number, _ := strconv.Atoi(strings.TrimRight(strings.TrimPrefix(self.String(), "M"), "ab"))
	return number
}

// The newest compute milestone whose exit has passed. Each milestone's gate sweep raises it, in §19.1's order, as it
// raises testdata/metadata/fields.yml's landed; a part that exits before one ahead of it in that order waits for it.
const computeInvariantsLanded = computeMilestoneM10

// The repos a row's tests may live in beside this module's, listed and not read here.
const (
	computeInvariantRepoServer = "server"
	computeInvariantRepoSdk    = "sdk"
)

// DESIGN-COMPUTE's section codes ("How to read"), which name the areas.
var computeInvariantAreaCodes = []string{
	"CCTX", "CTRUST", "CARCH", "PROV", "ATTEST", "INFER", "HARN", "GW", "BAL", "GAMMA", "ENC", "SSH", "GIT", "CSRV",
	"CSURF", "CACL", "CABUSE", "CTEST", "CPHASE", "SKILL", "SRCH", "FETCH", "MAILCAL", "CTXH", "CONN", "LSTN", "SAFE",
	"SUP",
}

// The tracks that own rows of an area with no plan tasks, with that area: §28's support skill was built from the design
// by its own track (support_skill_notes.md).
var computeInvariantTrackAreas = map[string]string{
	"support-skill": "SUP",
}

// A plan task's id: its area, its milestone's number and its place.
var computeInvariantTaskPattern = regexp.MustCompile(`^([A-Z]+)-M([0-9]{2})-[0-9]{2}$`)

// One of §2.4's invariants.
type computeInvariant struct {
	// IC-n, as §2.4 numbers it
	id string
	// one line pointing at §2.4's text, which governs
	summary string
	// the areas §2.4's text names as enforcing it, by DESIGN-COMPUTE's codes
	areas []string
	rows  []*computeInvariantRow
}

// One enforcing point of an invariant.
type computeInvariantRow struct {
	// the area that keeps it, one of its invariant's
	area string
	// what it holds
	point string
	// "" for this module, else computeInvariantRepoServer or computeInvariantRepoSdk
	repo string
	// its tests' package directory from its module's root, slash-separated: "." for the root
	pkg string
	// the top-level Test functions that prove it; none where its task's plan names none yet
	tests []string
	// the milestone whose exit brings them
	milestone computeMilestone
	// the plan task that owns them, or for an area with no plan tasks the track that built them
	task string
}

// §2.4's invariants, in its order.
var computeInvariantMatrix = []*computeInvariant{
	{
		id:      "IC-1",
		summary: "a call to a model labeled A1, A2 or AP reaches only an instance its provider lists, whose evidence the device verified within 10 minutes against the newest policy and a current ticket; a failure refuses, with no fallback",
		areas:   []string{"ATTEST", "INFER"},
		rows: []*computeInvariantRow{
			{
				area:      "ATTEST",
				point:     "the TDX verifier: a quote checked against the policy's profiles, its collateral fetched only by its client",
				pkg:       ".",
				tests:     []string{"TestTdxQuoteVerifies", "TestTdxNoNetworkOutsideCollateralClient"},
				milestone: computeMilestoneM14,
				task:      "ATTEST-M14-01",
			},
			{
				area:      "ATTEST",
				point:     "Chutes' instance evidence and NRAS's GPU token, each chained to its pinned root",
				pkg:       ".",
				tests:     []string{"TestChutesInstanceVerifies", "TestNrasTokenVerifies"},
				milestone: computeMilestoneM15,
				task:      "ATTEST-M15-01",
			},
			{
				area:      "INFER",
				point:     "only a listed instance whose evidence verified, chosen at random; a failed attestation refuses with no fallback",
				pkg:       ".",
				tests:     []string{"TestTeeInstanceNotInListRefused", "TestTeeFailedAttestationRefusesWithNoFallback", "TestTeeVerifiedInstanceChosenAtRandomByLoad"},
				milestone: computeMilestoneM15,
				task:      "INFER-M15-01",
			},
		},
	},
	{
		id:      "IC-2",
		summary: "prompts, outputs, tool calls and files leave a device only sealed to verified evidence, as EVS ciphertext or over Required mode; a direct call, a search, a calendar or service call, a fetch and a support message each only to its own hosts over TLS; servers see §14.6's rows",
		areas:   []string{"INFER", "SRCH", "FETCH", "MAILCAL", "CONN", "ENC", "SSH", "CSRV", "SUP"},
		rows: []*computeInvariantRow{
			{
				area:      "INFER",
				point:     "a call without a TEE only to its provider over TLS through auto egress, no byte sent before the checks",
				pkg:       ".",
				tests:     []string{"TestDirectNoByteBeforeChecks", "TestDirectNoConnectionReuse", "TestDirectBodyFromPolicyMapOnly"},
				milestone: computeMilestoneM12b,
				task:      "INFER-M12-03",
			},
			{
				area:      "INFER",
				point:     "a TEE call sealed to the key its verified evidence binds",
				pkg:       ".",
				tests:     []string{"TestTeeEnvelopeVectors"},
				milestone: computeMilestoneM15,
				task:      "INFER-M15-01",
			},
			{
				area:      "SRCH",
				point:     "a search only to Parallel's gateway over TLS through auto egress",
				pkg:       ".",
				tests:     []string{"TestWebSearchClientAutoEgress", "TestWebSearchClientBodyAndHeaders"},
				milestone: computeMilestoneM13b,
				task:      "SRCH-M13-02",
			},
			{
				area:      "FETCH",
				point:     "a fetch only to the site, through the network's egress, never directly",
				pkg:       ".",
				tests:     []string{"TestEgressThroughExit", "TestEgressNoDirectFallback"},
				milestone: computeMilestoneM13a,
				task:      "FETCH-M13-01",
			},
			{
				area:      "MAILCAL",
				point:     "a calendar call only to its link's hosts, through the network's egress or under direct",
				pkg:       ".",
				tests:     []string{"TestCalendarHttpExitRecordedAndShared", "TestCalendarHttpDirect", "TestCalendarHttpRefusals"},
				milestone: computeMilestoneM13a,
				task:      "MAILCAL-M13-03",
			},
			{
				area:      "CONN",
				point:     "a connected service's call only to its token and API hosts, through the network's egress or under direct",
				pkg:       ".",
				tests:     []string{"TestServiceEgressPinsExitByClientId", "TestServiceEgressDirect", "TestServiceEgressNoCredentialAcrossRedirect"},
				milestone: computeMilestoneM13a,
				task:      "CONN-M13-02",
			},
			{
				area:      "ENC",
				point:     "an enclave enrolls under the keys its evidence binds, its traffic Required mode as every sidecar's",
				pkg:       ".",
				tests:     []string{"TestEnrollWithAttestedKeys"},
				milestone: computeMilestoneM14,
				task:      "ENC-M14-10",
			},
			{
				area:      "SSH",
				point:     "SSH reaches an enclave only on its overlay address",
				pkg:       ".",
				tests:     []string{"TestSshServerOverlayOnly"},
				milestone: computeMilestoneM14,
				task:      "SSH-M14-02",
			},
			{
				area:      "CSRV",
				point:     "the broker keeps §14.6's rows and logs no body",
				pkg:       "computeservice",
				tests:     []string{"TestComputeServiceLogHoldsNoBody", "TestComputeSearchAuthorizeLeavesNoLogLine", "TestComputeKeyFamiliesHaveRows"},
				milestone: computeMilestoneM12a,
				task:      "CSRV-M12-01",
			},
			{
				area:      "SUP",
				point:     "a support message only to the feedback host the verified policy names, over TLS",
				pkg:       ".",
				tests:     []string{"TestSupportPostsOnlyToThePolicysHostOverTls"},
				milestone: computeMilestoneM13b,
				task:      "support-skill",
			},
		},
	},
	{
		id:      "IC-3",
		summary: "an enclave gets keys and credentials only sealed to a key bound in evidence a device of its network verified: an agents' enclave admitted only by its sponsor's verifying device, a mailbox grant only by the granting member's",
		areas:   []string{"ENC", "CACL"},
		rows: []*computeInvariantRow{
			{
				area:      "ENC",
				point:     "an incarnation admitted only by a device that verified its evidence; its bundle opens only with its provisioning key, erased after",
				pkg:       ".",
				tests:     []string{"TestEnclaveAdmitRefusesNonSigner", "TestEnclaveBundleOpensOnlyWithP", "TestEnclaveAuthKeyErased"},
				milestone: computeMilestoneM14,
				task:      "ENC-M14-09",
			},
			{
				area:      "ENC",
				point:     "setup over SSH: the evidence binds the keys the device admits, under the sponsor's statement",
				pkg:       ".",
				tests:     []string{"TestEnclaveSetupRelayedReportRefused", "TestEnclaveSetupOtherKeysRefused", "TestEnclaveSetupStatementCarried"},
				milestone: computeMilestoneM14,
				task:      "ENC-M14-18",
			},
			{
				area:      "ENC",
				point:     "a mailbox grant seated only by the granting member's device after its own verification",
				pkg:       ".",
				tests:     []string{"TestIndexerSeatAfterOwnVerification", "TestIndexerGrantSeatsOnlyThatMailbox", "TestIndexerSetupStatementSeating"},
				milestone: computeMilestoneM14,
				task:      "ENC-M14-26",
			},
			{
				area:      "CACL",
				point:     "repo keys by per-generation wraps, never an MLS leaf; one member's mailbox a seat",
				pkg:       ".",
				tests:     []string{"TestEnclaveTakesWrapsNeverALeaf", "TestMailboxSeatOneMemberOnly"},
				milestone: computeMilestoneM14,
				task:      "CACL-M14-01",
			},
		},
	},
	{
		id:      "IC-4",
		summary: "the compute balance and the transfer balance never convert, and neither pays for the other's charges",
		areas:   []string{"BAL"},
		rows: []*computeInvariantRow{
			{
				area:      "BAL",
				point:     "the ledger's own tables, sharing no column with the transfer balance's",
				pkg:       "model",
				tests:     []string{"TestComputeSchemaHoldsNoContentColumn"},
				milestone: computeMilestoneM12a,
				task:      "BAL-M12-01",
			},
			{
				area:      "BAL",
				point:     "the ledger's migrations apply on the private stack",
				repo:      computeInvariantRepoServer,
				pkg:       "computet3",
				tests:     []string{"TestComputeLedgerMigrationsApply"},
				milestone: computeMilestoneM12a,
				task:      "BAL-M12-01",
			},
			{
				area:      "BAL",
				point:     "lots credited only from compute purchases, once each; a chargeback reverses its own",
				repo:      computeInvariantRepoServer,
				pkg:       "computet3",
				tests:     []string{"TestComputeLotCreditedOnceByMarketRef", "TestComputeChargebackReversesSuspendsAndLapsesPromotions"},
				milestone: computeMilestoneM12a,
				task:      "BAL-M12-07",
			},
		},
	},
	{
		id:      "IC-5",
		summary: "local inference writes no charge and sends no request to a server; a web search is charged as a search",
		areas:   []string{"INFER", "BAL"},
		rows: []*computeInvariantRow{
			{
				area:      "INFER",
				point:     "local inference sends no request to a server",
				pkg:       ".",
				tests:     []string{"TestLocalInferenceMakesNoServerRequest"},
				milestone: computeMilestoneM11,
				task:      "INFER-M11-06",
			},
			{
				area:      "INFER",
				point:     "the router passes a local call whatever the floor, the budgets or the balance",
				pkg:       ".",
				tests:     []string{"TestCheckLocalPassesEveryFloorAndBudget"},
				milestone: computeMilestoneM11,
				task:      "INFER-M11-03",
			},
			{
				area:      "BAL",
				point:     "grace refuses remote calls and searches while local inference runs on",
				repo:      computeInvariantRepoServer,
				pkg:       "computet3",
				tests:     []string{"TestGraceRefusesCallsAndSearches"},
				milestone: computeMilestoneM12a,
				task:      "BAL-M12-12",
			},
		},
	},
	{
		id:      "IC-6",
		summary: "every compute debit is one charge row booked once under its operation key, its row committed before a provider is bound; no subject is charged past a budget that caps it",
		areas:   []string{"BAL", "CACL"},
		rows: []*computeInvariantRow{
			{
				area:      "BAL",
				point:     "one charge row a debit, booked once, its operation row committed before the provider is bound",
				repo:      computeInvariantRepoServer,
				pkg:       "computet3",
				tests:     []string{"TestComputeSettleDeliveredTwiceChargesOnce", "TestComputeStopBetweenHoldAndRowStrandsNoRoom", "TestComputeRowsHoldNoContent"},
				milestone: computeMilestoneM12a,
				task:      "BAL-M12-03",
			},
			{
				area:      "BAL",
				point:     "a hold refused past each budget that caps it, and below zero, each script acting once a key",
				repo:      computeInvariantRepoServer,
				pkg:       "computet3",
				tests:     []string{"TestComputeHoldRefusesPastEachBudget", "TestComputeHoldRefusesBelowZero", "TestComputeScriptsActOncePerOperationKey"},
				milestone: computeMilestoneM12a,
				task:      "BAL-M12-02",
			},
			{
				area:      "BAL",
				point:     "settlement survives every stop and a failover, the ledger's properties holding",
				repo:      computeInvariantRepoServer,
				pkg:       "computet3",
				tests:     []string{"TestComputeSettlementSurvivesEveryStop", "TestComputeLedgerProperties"},
				milestone: computeMilestoneM12a,
				task:      "BAL-M12-04",
			},
			{
				area:      "BAL",
				point:     "a direct call charged never past a cap, the rest absorbed by URnetwork",
				repo:      computeInvariantRepoServer,
				pkg:       "computet3",
				tests:     []string{"TestDirectCostlierReceiptChargesNoOnePastACap", "TestDirectBoundEnforcedAbsorbsNothing"},
				milestone: computeMilestoneM12b,
				task:      "BAL-M12-21",
			},
			{
				area:      "CACL",
				point:     "the device's budgets: each agent's, the device's ceiling, the policy's and a raise's",
				pkg:       ".",
				tests:     []string{"TestBudgetsForAgentCall", "TestBudgetDeviceCeilingAcrossAgents", "TestBudgetClampGrant"},
				milestone: computeMilestoneM12a,
				task:      "CACL-M12-05",
			},
		},
	},
	{
		id:      "IC-7",
		summary: "the local Harness starts no process, opens no host path outside its workspace, reaches the network only through the sidecar, and leaves no command a person's git, shell or editor would run",
		areas:   []string{"HARN", "GIT"},
		rows: []*computeInvariantRow{
			{
				area:      "HARN",
				point:     "the local profile's files import nothing that starts a process or opens a socket",
				pkg:       ".",
				tests:     []string{"TestHarnessLocalProfileImportsNoProcessOrSocket"},
				milestone: computeMilestoneM11,
				task:      "HARN-M11-05",
			},
			{
				area:      "HARN",
				point:     "the workspace confines every path: traversal, symlinks, absolute and Windows paths",
				pkg:       ".",
				tests:     []string{"TestHarnessWorkspaceRefusesTraversal", "TestHarnessWorkspaceRefusesSymlinkOut", "TestHarnessWorkspaceRefusesAbsoluteAndWindowsPaths"},
				milestone: computeMilestoneM11,
				task:      "HARN-M11-05",
			},
			{
				area:      "HARN",
				point:     "no path in a worktree's .git but through the bundled git, in any spelling",
				pkg:       ".",
				tests:     []string{"TestHarnessGitPathEverySpellingRefused"},
				milestone: computeMilestoneM11,
				task:      "HARN-M11-05",
			},
			{
				area:      "GIT",
				point:     "the bundled git writes no command into a worktree, and keeps a link out of it as text",
				pkg:       ".",
				tests:     []string{"TestConfigHoldsNoCommand", "TestPathSafetyCorpus", "TestSymlinkOutsideWorktreeAsText"},
				milestone: computeMilestoneM13a,
				task:      "GIT-M13-01",
			},
		},
	},
	{
		id:      "IC-8",
		summary: "an enclave's default egress is set by ur and enforced inside the enclave, failing closed; leaving through the provider's network takes an outward action",
		areas:   []string{"ENC", "CACL"},
		rows: []*computeInvariantRow{
			{
				area:      "ENC",
				point:     "the enclave's firewall ruleset, set by ur and failing closed",
				pkg:       ".",
				tests:     []string{"TestEnclaveFirewallRuleset", "TestEnclaveFirewallFailsClosed"},
				milestone: computeMilestoneM14,
				task:      "ENC-M14-11",
			},
			{
				area:      "ENC",
				point:     "each egress mode's routes; a mode the daemon cannot apply leaves no default route; direct files kind 20",
				pkg:       ".",
				tests:     []string{"TestEnclaveEgressModes", "TestEnclaveEgressFailsClosed", "TestEnclaveEgressDirectKind20"},
				milestone: computeMilestoneM14,
				task:      "ENC-M14-12",
			},
			{
				area:      "CACL",
				point:     "kind 20, leaving through the provider's network, an outward action with its own row",
				pkg:       ".",
				tests:     []string{"TestVersion5KindRows"},
				milestone: computeMilestoneM12a,
				task:      "CACL-M12-01",
			},
		},
	},
	{
		id:      "IC-9",
		summary: "the attestation policy is signed by the compute-policy key the release key certifies and only moves forward; tickets make a revocation bind within 72 hours, and a device that saw a newer version does no remote work under an older one",
		areas:   []string{"ATTEST"},
		rows: []*computeInvariantRow{
			{
				area:      "ATTEST",
				point:     "a policy verifies only under the certified key; the store takes only a higher version and keeps the highest seen",
				pkg:       ".",
				tests:     []string{"TestComputePolicyVerifies", "TestComputePolicyStoreTakesOnlyHigher", "TestComputePolicyHighestSeenPersists"},
				milestone: computeMilestoneM11,
				task:      "ATTEST-M11-01",
			},
			{
				area:      "ATTEST",
				point:     "a ticket current for 72 hours from its start, never past its batch's expiry or the policy's not_after; a newer version seen stops remote work",
				pkg:       ".",
				tests:     []string{"TestTicketReleasedHonoredFor72Hours", "TestTicketBatchPastFourteenDaysRefused", "TestTicketNeverCarriesPolicyPastNotAfter", "TestNewerVersionSeenStopsRemoteWork"},
				milestone: computeMilestoneM12a,
				task:      "ATTEST-M12-01",
			},
		},
	},
	{
		id:      "IC-10",
		summary: "users hold, see and move no gamma, TAO, alpha or USDC; the treasury's, spend and payer keys never reach a device, which carries at most a one-search authorization within the policy's ceiling to the payee it named",
		areas:   []string{"GAMMA", "SRCH", "BAL"},
		rows: []*computeInvariantRow{
			{
				area:      "GAMMA",
				point:     "TAO withdrawn only to the mint coldkey; no route answers the treasury's state",
				pkg:       "computeservice",
				tests:     []string{"TestGammaVenueWithdrawsOnlyToTheColdkey", "TestNoRouteAnswersTreasuryState"},
				milestone: computeMilestoneM12b,
				task:      "GAMMA-M12-04",
			},
			{
				area:      "SRCH",
				point:     "the signer signs one search's authorization within the policy's ceiling and asset, knowing no network",
				pkg:       "searchsigner",
				tests:     []string{"TestSearchSignerSignsTicket", "TestSearchSignerRefusesCeilingAndAsset", "TestSearchSignerNoNetworkAnywhere"},
				milestone: computeMilestoneM13b,
				task:      "SRCH-M13-03",
			},
			{
				area:      "SRCH",
				point:     "a payee the sanctions screen lists, or one not fresh, refused",
				pkg:       "searchsigner",
				tests:     []string{"TestSearchScreenRefusesListed", "TestSearchScreenPayeeFresh"},
				milestone: computeMilestoneM13b,
				task:      "SRCH-M13-05",
			},
			{
				area:      "BAL",
				point:     "the search cap and the daily load bound what a network can move",
				repo:      computeInvariantRepoServer,
				pkg:       "computet3",
				tests:     []string{"TestComputeSearchCapByPaidLotAge", "TestComputeDailyLoadStopsNetworkAndPayer"},
				milestone: computeMilestoneM12a,
				task:      "BAL-M12-07",
			},
		},
	},
	{
		id:      "IC-11",
		summary: "a gateway token administers, signs and reads nothing but its own grant's budget state, spending within it, on loopback, for at most an hour",
		areas:   []string{"GW"},
		rows: []*computeInvariantRow{
			{
				area:      "GW",
				point:     "a token reaches only its own grant, for an hour; a revoked grant's tokens refused",
				pkg:       ".",
				tests:     []string{"TestTokenReachesOnlyItsGrant", "TestTokenFormatAndHourLife", "TestRevokedGrantRefusesItsTokens"},
				milestone: computeMilestoneM12a,
				task:      "GW-M12-02",
			},
			{
				area:      "GW",
				point:     "a runner's key refused anywhere but its own host and origin",
				pkg:       ".",
				tests:     []string{"TestRunnerKeyRefusedElsewhere", "TestRunnerHostOriginChecks"},
				milestone: computeMilestoneM12a,
				task:      "GW-M12-08",
			},
			{
				area:      "GW",
				point:     "in an enclave's agents' container, tokens only through its socket and the listener only in its namespace",
				pkg:       ".",
				tests:     []string{"TestContainerTokensOnlyThroughSocket", "TestContainerListenerOnlyInNamespace"},
				milestone: computeMilestoneM14,
				task:      "GW-M14-01",
			},
		},
	},
	{
		id:      "IC-12",
		summary: "an inbox message, a status or summary, or an attach-link command is untrusted and taints the run that takes it unless its provenance shows the member's own person or an untainted own run; a support notice is neither trusted nor tainting",
		areas:   []string{"SKILL", "HARN", "GIT", "CTXH", "SUP"},
		rows: []*computeInvariantRow{
			{
				area:      "SKILL",
				point:     "a message's trust by its provenance; no write under inbox/ by any path",
				pkg:       ".",
				tests:     []string{"TestTrustClasses", "TestInboxWriteRefusedEverywhere"},
				milestone: computeMilestoneM11,
				task:      "SKILL-M11-04",
			},
			{
				area:      "SKILL",
				point:     "a card a forged writer wrote is ignored",
				pkg:       ".",
				tests:     []string{"TestCardForgedWriterIgnored"},
				milestone: computeMilestoneM11,
				task:      "SKILL-M11-02",
			},
			{
				area:      "SKILL",
				point:     "an untrusted writer's status and summary text only with include, its stubs withholding what is off grammar",
				pkg:       ".",
				tests:     []string{"TestUntrustedWriterTextOnlyWithInclude", "TestStubFieldsWithheldOffGrammar"},
				milestone: computeMilestoneM11,
				task:      "SKILL-M11-03",
			},
			{
				area:      "SKILL",
				point:     "another member's message taints its reader and waits for the person's turn",
				pkg:       ".",
				tests:     []string{"TestCrossMemberMessageTaintsReader", "TestOutsideMessageWaitsForPersonTurn"},
				milestone: computeMilestoneM13b,
				task:      "SKILL-M13-01",
			},
			{
				area:      "HARN",
				point:     "taint written before a result returns, and never cleared",
				pkg:       ".",
				tests:     []string{"TestHarnessTaintFsyncsBeforeResultReturns", "TestHarnessMarkFsyncsAndNeverClears", "TestHarnessRunReadsTaintedWithoutFile"},
				milestone: computeMilestoneM11,
				task:      "HARN-M11-02",
			},
			{
				area:      "HARN",
				point:     "an EVS version or record row of untrusted provenance taints first; inbox writes refused",
				pkg:       ".",
				tests:     []string{"TestHarnessEvsReadUntrustedProvenanceTaintsFirst", "TestHarnessRecordQueryIncludeTaintsFirst", "TestHarnessEvsWriteUnderInboxRefused"},
				milestone: computeMilestoneM11,
				task:      "HARN-M11-06",
			},
			{
				area:      "HARN",
				point:     "a link command arrives untrusted unless its signed origin shows the person or an untainted own run",
				pkg:       ".",
				tests:     []string{"TestHarnessForgedLineOriginArrivesUntrusted", "TestHarnessUnsignedSessionIsUnknownRun", "TestHarnessTaggedCallerTaintsReceiver", "TestHarnessOtherMemberUntrustedAndCannotLaunch"},
				milestone: computeMilestoneM14,
				task:      "HARN-M14-02",
			},
			{
				area:      "GIT",
				point:     "a fetch of a tainted push taints the run before the worktree changes",
				pkg:       ".",
				tests:     []string{"TestFetchOfTaintedPushTaintsBeforeWorktree"},
				milestone: computeMilestoneM13a,
				task:      "GIT-M13-02",
			},
			{
				area:      "CTXH",
				point:     "a node a tainted run or another member's enclave wrote taints the run that continues from it",
				pkg:       ".",
				tests:     []string{"TestSessionFlaggedNodeTaintsContinuation", "TestSessionOtherMembersEnclaveNodeWithBitClearedTaints"},
				milestone: computeMilestoneM11,
				task:      "CTXH-M11-05",
			},
			{
				area:      "CTXH",
				point:     "an untrusted node read back only as a stub unless asked for",
				pkg:       ".",
				tests:     []string{"TestRecordQueryUntrustedNodeStubUnlessInclude"},
				milestone: computeMilestoneM11,
				task:      "CTXH-M11-04",
			},
			{
				area:      "CTXH",
				point:     "ur harness show taints the runs above its caller",
				pkg:       "cli",
				tests:     []string{"TestUrHarnessShowTaintsAncestorRuns"},
				milestone: computeMilestoneM11,
				task:      "CTXH-M11-04",
			},
			{
				area:      "SUP",
				point:     "support's events received and notified as enumerated fields, never their text",
				pkg:       ".",
				tests:     []string{"TestSupportEventsAreReceivedOnceRecordedAndNotifiedWithoutText"},
				milestone: computeMilestoneM13b,
				task:      "support-skill",
			},
		},
	},
	{
		id:      "IC-13",
		summary: "the broker logs no request body, envelope byte or SSH byte, and keeps §14.6's rows and nothing else",
		areas:   []string{"CSRV"},
		rows: []*computeInvariantRow{
			{
				area:      "CSRV",
				point:     "the broker's log holds no body, header value or path value; a search's admission leaves no line",
				pkg:       "computeservice",
				tests:     []string{"TestComputeServiceLogHoldsNoBody", "TestComputeSearchAuthorizeLeavesNoLogLine"},
				milestone: computeMilestoneM12a,
				task:      "CSRV-M12-01",
			},
			{
				area:      "CSRV",
				point:     "every key family the broker writes has its §14.6 row, under one hash tag a script",
				pkg:       "computeservice",
				tests:     []string{"TestComputeKeyFamiliesHaveRows", "TestComputeKeysKeepOneTagAScript"},
				milestone: computeMilestoneM12a,
				task:      "CSRV-M12-01",
			},
		},
	},
	{
		id:      "IC-14",
		summary: "an enclave's SSH server listens only on its overlay address for an admitted sidecar's key whose flow principal matches, root only from the sponsor's untagged devices; the agents' container holds no key, token or link secret and reaches the daemon only as a tainted run",
		areas:   []string{"SSH", "ENC"},
		rows: []*computeInvariantRow{
			{
				area:      "SSH",
				point:     "the server listens only on the overlay and takes only a live admitted key whose flow principal matches",
				pkg:       ".",
				tests:     []string{"TestSshServerOverlayOnly", "TestSshServerRefusals", "TestSshServerAcceptsLiveKeyAndPrincipal"},
				milestone: computeMilestoneM14,
				task:      "SSH-M14-02",
			},
			{
				area:      "SSH",
				point:     "origins verified, and the Harness joined, outside the agents' container",
				pkg:       ".",
				tests:     []string{"TestSshOriginRefusals", "TestSshHarnessRpcJoinedOutsideContainer"},
				milestone: computeMilestoneM14,
				task:      "SSH-M14-04",
			},
			{
				area:      "ENC",
				point:     "the agents' container holds no secret and reaches only DNS in the enclave's namespaces",
				pkg:       ".",
				tests:     []string{"TestEnclaveContainerHoldsNoSecret", "TestEnclaveContainerReachesOnlyDns"},
				milestone: computeMilestoneM14,
				task:      "ENC-M14-13",
			},
			{
				area:      "ENC",
				point:     "every container-socket call a tainted run's, the gateway's token through it alone",
				pkg:       ".",
				tests:     []string{"TestEnclaveContainerSocketTaintsEveryResult", "TestEnclaveContainerSocketKindsTainted", "TestEnclaveContainerSocketGatewayToken"},
				milestone: computeMilestoneM14,
				task:      "ENC-M14-14",
			},
			{
				area:      "ENC",
				point:     "the SSH host key stays in the daemon",
				pkg:       ".",
				tests:     []string{"TestEnclaveHostKeyStaysInDaemon"},
				milestone: computeMilestoneM14,
				task:      "ENC-M14-15",
			},
		},
	},
	{
		id:      "IC-15",
		summary: "a web search query reaches no URnetwork server: the device sends it to Parallel's gateway itself, paid by an authorization the separate signer signs within the ceiling and the network's budgets",
		areas:   []string{"SRCH"},
		rows: []*computeInvariantRow{
			{
				area:      "SRCH",
				point:     "the device sends the query to the gateway itself, through auto egress, paying once, refusing an offer off the policy",
				pkg:       ".",
				tests:     []string{"TestWebSearchClientAutoEgress", "TestWebSearchClientPaysOnce", "TestWebSearchClientRefusesBadOffer"},
				milestone: computeMilestoneM13b,
				task:      "SRCH-M13-02",
			},
			{
				area:      "SRCH",
				point:     "the broker holds and relays the sealed authorization unread, seeing no payee or nonce",
				pkg:       "computeservice",
				tests:     []string{"TestSearchAdmitHoldsAndRelays", "TestSearchAdmitNoPayeeNoNonce"},
				milestone: computeMilestoneM13b,
				task:      "SRCH-M13-07",
			},
			{
				area:      "SRCH",
				point:     "the signer, apart from the broker, signs a nonce once and knows no network",
				pkg:       "searchsigner",
				tests:     []string{"TestSearchSignerRefusesNonceReuse", "TestSearchSignerNoNetworkAnywhere"},
				milestone: computeMilestoneM13b,
				task:      "SRCH-M13-03",
			},
		},
	},
	{
		id:      "IC-16",
		summary: "a web fetch reaches only public addresses, by GET without cookies or credentials, through the network's egress; a URL a tainted run composed waits for an approval, the person's or the classifier's in auto mode",
		areas:   []string{"FETCH", "CACL", "SAFE"},
		rows: []*computeInvariantRow{
			{
				area:      "FETCH",
				point:     "public addresses only, a rebinding pinned, never a direct fallback",
				pkg:       ".",
				tests:     []string{"TestEgressAddressCheckCorpus", "TestEgressRebindPinned", "TestEgressNoDirectFallback"},
				milestone: computeMilestoneM13a,
				task:      "FETCH-M13-01",
			},
			{
				area:      "FETCH",
				point:     "a URL a tainted run composed files kind 23 unless listed",
				pkg:       ".",
				tests:     []string{"TestWebFetchTaintedComposedIsKind23", "TestWebFetchListedSources"},
				milestone: computeMilestoneM13a,
				task:      "FETCH-M13-04",
			},
			{
				area:      "CACL",
				point:     "kind 23's card: its host in punycode, hidden characters escaped",
				pkg:       ".",
				tests:     []string{"TestRenderVersion5Goldens", "TestRenderHostsInPunycode", "TestRenderEscapesBidiAndInvisible"},
				milestone: computeMilestoneM12a,
				task:      "CACL-M12-02",
			},
			{
				area:      "SAFE",
				point:     "the classifier approves a tainted run's fetch in auto mode only within auto_ok, on a site the member has used; kinds 23 and 25 end to end",
				pkg:       ".",
				milestone: computeMilestoneM13a,
				task:      "SAFE-M13-14",
			},
		},
	},
	{
		id:      "IC-17",
		summary: "a call to a model without a TEE carries the broker's btauth/1 signature over the request's hash, for the host and receiver the policy pins, after its checks; the hash kept only until the call settles, at most 10 minutes, never logged",
		areas:   []string{"INFER", "PROV", "BAL"},
		rows: []*computeInvariantRow{
			{
				area:      "INFER",
				point:     "the broker signs btauth/1 only for the policy's host and receiver, holding the declared model's worst case first",
				pkg:       "computeservice",
				tests:     []string{"TestAuthorizeRefusesHostOrReceiverOffPolicy", "TestAuthorizeHoldsDeclaredWorstCase", "TestBtauthMessageVectors"},
				milestone: computeMilestoneM12b,
				task:      "INFER-M12-04",
			},
			{
				area:      "INFER",
				point:     "the hash dropped within 10 minutes and never logged",
				pkg:       "computeservice",
				tests:     []string{"TestHashDroppedAfterTenMinutes", "TestAuthorizeLogsNoHash"},
				milestone: computeMilestoneM12b,
				task:      "INFER-M12-04",
			},
			{
				area:      "INFER",
				point:     "a random value in the body; the hashed bytes sent once",
				pkg:       ".",
				tests:     []string{"TestDirectBodyCarriesRandomUserAndDirectSalt", "TestDirectSendsHashedBytesOnce"},
				milestone: computeMilestoneM12b,
				task:      "INFER-M12-03",
			},
			{
				area:      "INFER",
				point:     "a call settled against its provider's receipt by the kept hash; a mismatch flags the network",
				pkg:       "computeservice",
				tests:     []string{"TestSettleReceiptAgainstKeptHash", "TestMismatchFlagsNetwork"},
				milestone: computeMilestoneM12b,
				task:      "INFER-M12-05",
			},
			{
				area:      "PROV",
				point:     "engy's target from the policy's map; its receipt verified",
				pkg:       ".",
				tests:     []string{"TestEngyDirectTargetComesFromThePolicy", "TestEngyReceiptVerifies", "TestEngyBodyCarriesZdrAndRandomUser"},
				milestone: computeMilestoneM12b,
				task:      "PROV-M12-02",
			},
			{
				area:      "PROV",
				point:     "SayGM's upstream only from the policy; no settlement without a receipt",
				pkg:       "computeservice",
				tests:     []string{"TestSaygmUpstreamHeaderOnlyFromPolicy", "TestSaygmSettlementRefusedWithoutReceiptOrListing"},
				milestone: computeMilestoneM12b,
				task:      "PROV-M12-03",
			},
			{
				area:      "BAL",
				point:     "a direct call's open shortfalls held within their bound before the broker signs",
				repo:      computeInvariantRepoServer,
				pkg:       "computet3",
				tests:     []string{"TestDirectOpenShortfallsHeldWithinFiveDollars", "TestDirectSmallBalanceCallAdmitted"},
				milestone: computeMilestoneM12b,
				task:      "BAL-M12-21",
			},
		},
	},
	{
		id:      "IC-18",
		summary: "a calendar link's credential is read only by its member's consented devices' calendar tools and enters no context, result, record, approval, error or log; a tainted write, or one with attendees, is kind 25, bound to its link and checked again when sent",
		areas:   []string{"MAILCAL", "CACL", "CTRUST"},
		rows: []*computeInvariantRow{
			{
				area:      "MAILCAL",
				point:     "a link's secret in its own secret repo, opened by no audit reader, never logged",
				pkg:       ".",
				tests:     []string{"TestCalendarLinkAuditReaderOpensNothing", "TestCalendarLinkSecretNeverLogged", "TestCalendarLinkStoreSaveListOpen"},
				milestone: computeMilestoneM13a,
				task:      "MAILCAL-M13-01",
			},
			{
				area:      "MAILCAL",
				point:     "a tainted write, and any with attendees, files kind 25",
				pkg:       ".",
				tests:     []string{"TestCalendarAddTaintedFilesKind25", "TestCalendarAddAttendeesAlwaysKind25"},
				milestone: computeMilestoneM13a,
				task:      "MAILCAL-M13-05",
			},
			{
				area:      "MAILCAL",
				point:     "an approved write only to the link and calendar its decision binds, checked when sent; a lost answer resent only on the person's",
				pkg:       ".",
				tests:     []string{"TestCalendarDispatchDestinationChanged", "TestCalendarReconcileRequiredUntilAnswered", "TestCalendarRetryWritesNothingTwice"},
				milestone: computeMilestoneM13a,
				task:      "MAILCAL-M13-07",
			},
			{
				area:      "CACL",
				point:     "kind 25's row, its events bounded",
				pkg:       ".",
				tests:     []string{"TestVersion5KindRows", "TestCalendarEventCount"},
				milestone: computeMilestoneM12a,
				task:      "CACL-M12-01",
			},
			{
				area:      "CTRUST",
				point:     "a link's secret in the daemon's matcher: refused in a result, matched in an error, never named when its source fails",
				pkg:       ".",
				tests:     []string{"TestComputeCustodyCredentialMatched", "TestComputeCustodyNoValueInError", "TestComputeCustodySourceFailsClosed"},
				milestone: computeMilestoneM13a,
				task:      "CTRUST-M13-01",
			},
		},
	},
	{
		id:      "IC-19",
		summary: "a Harness or gateway model call is sent only after every item of its context is journaled, each response item journaled before the event completing it, the entries leaving only sealed",
		areas:   []string{"CTXH"},
		rows: []*computeInvariantRow{
			{
				area:      "CTXH",
				point:     "every context item journaled before the call, each response item before the tool it asks for",
				pkg:       ".",
				tests:     []string{"TestSessionKilledBetweenJournalAndCall", "TestSessionKilledBetweenResponseAndTool", "TestSessionNoBytesAcrossRuns"},
				milestone: computeMilestoneM11,
				task:      "CTXH-M11-03",
			},
			{
				area:      "CTXH",
				point:     "mail as a reference re-rendered and checked; search results and keep false details kept as stubs",
				pkg:       ".",
				tests:     []string{"TestSessionMailReferenceHashOfTextRead", "TestSessionSyntheticSearchResultsInNoNodeOrBlob", "TestSessionKeepFalseFromNonBuiltInIgnored"},
				milestone: computeMilestoneM11,
				task:      "CTXH-M11-03",
			},
			{
				area:      "CTXH",
				point:     "the rebuild corpus: each call rebuilt from the vault to its request hash, writers and chains verified",
				pkg:       ".",
				tests:     []string{"TestSessionRebuildCorpusMatchesRequestHashes", "TestSessionReaderVerifiesWritersChainsAndParents", "TestSessionRendererGoldens"},
				milestone: computeMilestoneM11,
				task:      "CTXH-M11-04",
			},
			{
				area:      "CTXH",
				point:     "the gateway's items journaled before their output item completes, a cut call recorded once",
				pkg:       ".",
				tests:     []string{"TestSessionGatewayItemJournaledBeforeOutputItemDone", "TestSessionGatewayCutCallRetryRecordedOnce"},
				milestone: computeMilestoneM12a,
				task:      "CTXH-M12-01",
			},
		},
	},
	{
		id:      "IC-20",
		summary: "a connection's OAuth credentials live only in its own secret repo, written before use, read only by its member's consented devices' connection clients, in no context, result, record, approval, error or log; a tainted run's write is kind 26",
		areas:   []string{"CONN", "CACL", "CTRUST"},
		rows: []*computeInvariantRow{
			{
				area:      "CONN",
				point:     "tokens written to the connection's secret repo before first use; access tokens never persisted",
				pkg:       ".",
				tests:     []string{"TestConnectionTokenWrittenBeforeUse", "TestConnectionAccessTokenNeverPersisted", "TestConnectionAuditReaderReadsRecordNotTokens"},
				milestone: computeMilestoneM13b,
				task:      "CONN-M13-04",
			},
			{
				area:      "CONN",
				point:     "each token sealed to the consented devices' ReaderKeys, a Google token to its platform's alone",
				pkg:       ".",
				tests:     []string{"TestDeviceSealAuditReaderOpensNone", "TestDeviceSealOtherPlatformOpensNone", "TestDeviceSealTaggedSidecarOpensNone"},
				milestone: computeMilestoneM13a,
				task:      "CONN-M13-01",
			},
			{
				area:      "CONN",
				point:     "a strictly rotating token presented once a generation; access tokens in memory only",
				pkg:       ".",
				tests:     []string{"TestStrictRefreshLostAnswerNoResubmit", "TestAccessTokenOnlyInMemory", "TestPerPlatformTokenUnusedElsewhere"},
				milestone: computeMilestoneM13b,
				task:      "CONN-M13-06",
			},
			{
				area:      "CONN",
				point:     "no token in a result or a request; a tainted run's write files kind 26; a clean run's send asks nothing",
				pkg:       ".",
				tests:     []string{"TestServiceCallCanaryToken", "TestServiceCallSecretInRequest", "TestServiceCallTaintedWriteFilesKind26", "TestServiceCallUntaintedSendNoApproval"},
				milestone: computeMilestoneM13b,
				task:      "CONN-M13-08",
			},
			{
				area:      "CONN",
				point:     "a limited_use read marks its run, written ahead and kept",
				pkg:       ".",
				tests:     []string{"TestLimitedUseMarkWriteAheadAndKept", "TestLimitedUseMcpUnboundSessionRefused"},
				milestone: computeMilestoneM13b,
				task:      "CONN-M13-07",
			},
			{
				area:      "CACL",
				point:     "kind 26's card, its body shown whole and escaped",
				pkg:       ".",
				tests:     []string{"TestRenderVersion5Goldens", "TestRenderEscapesBidiAndInvisible"},
				milestone: computeMilestoneM12a,
				task:      "CACL-M12-02",
			},
			{
				area:      "CTRUST",
				point:     "connections' credentials in the daemon's matcher",
				pkg:       ".",
				tests:     []string{"TestComputeCustodyCredentialMatched", "TestComputeCustodyNoValueInError"},
				milestone: computeMilestoneM13a,
				task:      "CTRUST-M13-01",
			},
		},
	},
	{
		id:      "IC-21",
		summary: "a device lists only what its own tables show and publishes only as EVS ciphertext once listeners:publish is acknowledged; the listeners rule admits a flow only to a listed socket or map entry, delivered as the network's traffic",
		areas:   []string{"LSTN", "CTRUST"},
		rows: []*computeInvariantRow{
			{
				area:      "LSTN",
				point:     "discovery reads the OS's tables and opens no inet socket",
				pkg:       ".",
				tests:     []string{"TestListenersDiscoveryOpensNoInetSocket"},
				milestone: computeMilestoneM13a,
				task:      "LSTN-M13-02",
			},
			{
				area:      "LSTN",
				point:     "the listed set holds only socket and map entries neither shared nor hidden, loopback binds kept to the person's devices",
				pkg:       ".",
				milestone: computeMilestoneM13a,
				task:      "LSTN-M13-04",
			},
			{
				area:      "LSTN",
				point:     "the hook admits only a listed entry, never at loopback, a forward, a shared port or rule 0's",
				pkg:       "device",
				milestone: computeMilestoneM13a,
				task:      "LSTN-M13-07",
			},
			{
				area:      "LSTN",
				point:     "the host delivers a listener flow as the network's traffic",
				pkg:       "device",
				milestone: computeMilestoneM13a,
				task:      "LSTN-M13-09",
			},
			{
				area:      "LSTN",
				point:     "publishing waits for the acknowledgment, a desktop's confirmed first list and, for a tagged sidecar, the network's statement",
				pkg:       ".",
				milestone: computeMilestoneM13a,
				task:      "LSTN-M13-10",
			},
			{
				area:      "CTRUST",
				point:     "listeners:publish acknowledged only by the person's own act, a new version asking again after its grace",
				pkg:       ".",
				tests:     []string{"TestDisclosureAckOnlyByPerson", "TestDisclosureNewVersionGrace"},
				milestone: computeMilestoneM12a,
				task:      "CTRUST-M12-01",
			},
			{
				area:      "CTRUST",
				point:     "a tagged sidecar covered only while an Owner's or Admin's statement stands",
				pkg:       ".",
				tests:     []string{"TestNetworkDisclosureCoversTaggedRunner", "TestNetworkDisclosureRefusals"},
				milestone: computeMilestoneM12a,
				task:      "CTRUST-M12-02",
			},
		},
	},
	{
		id:      "IC-22",
		summary: "an approval that exists only because a run is tainted, of kinds 23 to 27, may be the classifier's, on the requesting device, by the pinned model over every tainting input, only where auto is allowed and approvals:auto acknowledged; spendable only by its signer, never shown as a person's",
		areas:   []string{"SAFE", "CACL", "CTRUST"},
		rows: []*computeInvariantRow{
			{
				area:      "SAFE",
				point:     "scores over every input that tainted the run, an unregistered read giving inputs_unknown",
				pkg:       ".",
				milestone: computeMilestoneM13a,
				task:      "SAFE-M13-04",
			},
			{
				area:      "SAFE",
				point:     "auto_ok's conditions, §27.7's always-ask rules whatever the score, and the limits",
				pkg:       ".",
				milestone: computeMilestoneM13a,
				task:      "SAFE-M13-06",
			},
			{
				area:      "SAFE",
				point:     "the decision on channel auto, its verdict entry journaled before the effect, spent once",
				pkg:       ".",
				milestone: computeMilestoneM13a,
				task:      "SAFE-M13-09",
			},
			{
				area:      "SAFE",
				point:     "an enclave's daemon deciding only its own runs' requests",
				pkg:       ".",
				milestone: computeMilestoneM14,
				task:      "SAFE-M14-01",
			},
			{
				area:      "CACL",
				point:     "an automatic decision spendable only by its signer, never at a gate or for a grant; an evidence list without auto forces an ask",
				pkg:       ".",
				tests:     []string{"TestAutoDecisionSpendRules", "TestEvidenceListWithoutAutoForcesAsk", "TestAutoCapableEnclaveOwnRunsOnly"},
				milestone: computeMilestoneM13a,
				task:      "CACL-M13-01",
			},
			{
				area:      "CACL",
				point:     "version 3 on channel auto only; the auto fields only on their kinds",
				pkg:       ".",
				tests:     []string{"TestDecisionVersion3ChannelAutoOnly", "TestAutoFieldsOnlyOnKinds23To26"},
				milestone: computeMilestoneM12a,
				task:      "CACL-M12-01",
			},
			{
				area:      "CTRUST",
				point:     "approvals:auto acknowledged only by the person's own act",
				pkg:       ".",
				tests:     []string{"TestDisclosureAckOnlyByPerson"},
				milestone: computeMilestoneM12a,
				task:      "CTRUST-M12-01",
			},
		},
	},
	{
		id:      "IC-23",
		summary: "an agents' enclave's incarnation is one of its sponsor's devices, admitted by the sponsor's verifying untagged device, signing nothing but its own, revoked at its stop, its container holding none of the daemon's secrets; the indexer enclave is no member's device",
		areas:   []string{"ENC", "CACL"},
		rows: []*computeInvariantRow{
			{
				area:      "ENC",
				point:     "the admission names the sponsor, signed by the sponsor's verifying untagged device; a SponsorSet naming it refused",
				pkg:       ".",
				tests:     []string{"TestEnclaveAdmissionSigners", "TestEnclaveAdmissionShape", "TestEnclaveSponsorSetRefused"},
				milestone: computeMilestoneM14,
				task:      "ENC-M14-03",
			},
			{
				area:      "ENC",
				point:     "the daemon signs nothing but its own and reads only the sponsor's settings",
				pkg:       ".",
				tests:     []string{"TestEnclaveDaemonSignsNothingButItsOwn", "TestEnclaveDaemonReadsSponsorSettingsOnly"},
				milestone: computeMilestoneM14,
				task:      "ENC-M14-15",
			},
			{
				area:      "ENC",
				point:     "no device takes the enclave's version of the sponsor's settings",
				pkg:       ".",
				tests:     []string{"TestEnclaveSettingsIgnoresEnclaveWriter"},
				milestone: computeMilestoneM14,
				task:      "ENC-M14-02",
			},
			{
				area:      "ENC",
				point:     "its stop, loss or compromise revokes it, every repo it read moving to a new generation",
				pkg:       ".",
				tests:     []string{"TestEnclaveStopRevokesAndRotates", "TestEnclaveLostRevokedByHousekeeping"},
				milestone: computeMilestoneM14,
				task:      "ENC-M14-24",
			},
			{
				area:      "ENC",
				point:     "the agents' container holds none of the daemon's keys, tokens or link secrets",
				pkg:       ".",
				tests:     []string{"TestEnclaveContainerHoldsNoSecret"},
				milestone: computeMilestoneM14,
				task:      "ENC-M14-13",
			},
			{
				area:      "CACL",
				point:     "bit 3's predicates: an agents' enclave signs no consent, admission or tag",
				pkg:       ".",
				tests:     []string{"TestConsentSignersRefuseBit3", "TestAdmissionSignersRefuseBit3", "TestCanApplyTagRefusesBit3", "TestPredicatesFromRowsAlone"},
				milestone: computeMilestoneM13a,
				task:      "CACL-M13-01",
			},
			{
				area:      "CACL",
				point:     "evs_member and mailbox_seat; the gkm form's signers refuse bit 3",
				pkg:       ".",
				tests:     []string{"TestEvsMemberMatrix", "TestMailboxSeatOneMemberOnly", "TestGkmFormSignerRefusesBit3"},
				milestone: computeMilestoneM14,
				task:      "CACL-M14-01",
			},
		},
	},
	{
		id:      "IC-24",
		summary: "a support message, its bundle and its files leave only for the verified policy's feedback host over TLS, from a support client; an agent's holds nothing the secret scan matches and goes without a person only from a clean run; the bundle holds only the registry's codes and fields",
		areas:   []string{"SUP", "ATTEST", "SAFE", "CTRUST"},
		rows: []*computeInvariantRow{
			{
				area:      "SUP",
				point:     "a message posted only to the policy's host over TLS, the policy's line read strictly",
				pkg:       ".",
				tests:     []string{"TestSupportPostsOnlyToThePolicysHostOverTls", "TestSupportPolicyLineParsesStrictly"},
				milestone: computeMilestoneM13b,
				task:      "support-skill",
			},
			{
				area:      "SUP",
				point:     "an agent's message holding a secret refused; a clean run's goes without a person; any other files kind 27",
				pkg:       ".",
				tests:     []string{"TestSupportRefusesAnAgentsSecretAndWarnsThePerson", "TestSupportCleanHarnessRunsMessageGoesWithoutApproval", "TestSupportOutwardMessagesFileKind27"},
				milestone: computeMilestoneM13b,
				task:      "support-skill",
			},
			{
				area:      "SUP",
				point:     "nothing sent without the current disclosure's acknowledgment",
				pkg:       ".",
				tests:     []string{"TestSupportRefusesWithoutTheCurrentDisclosure"},
				milestone: computeMilestoneM13b,
				task:      "support-skill",
			},
			{
				area:      "SUP",
				point:     "the support log's ring and bundles hold only the registry's codes and enumerated fields",
				pkg:       ".",
				tests:     []string{"TestSupportLogCanaryCorpusLeavesNoByteInARingOrABundle", "TestSupportLogRefusesAndCountsFieldsTheCodeDoesNotDeclare"},
				milestone: computeMilestoneM11,
				task:      "support-skill",
			},
			{
				area:      "SUP",
				point:     "the tools stay unlisted while the release's switch is off",
				pkg:       "mcp",
				tests:     []string{"TestSupportToolsStayUnlistedWhileTheReleaseSwitchIsOff"},
				milestone: computeMilestoneM13b,
				task:      "support-skill",
			},
			{
				area:      "ATTEST",
				point:     "the host read only from the newest verified policy's support line, kept verbatim",
				pkg:       ".",
				tests:     []string{"TestSidecarSupportReadsThePolicysSupportLine", "TestComputePolicySupportLineSurvivesVerbatim"},
				milestone: computeMilestoneM12a,
				task:      "ATTEST-M12-02",
			},
			{
				area:      "SAFE",
				point:     "a tainted run's message decided by the classifier only under IC-22's rules",
				pkg:       ".",
				milestone: computeMilestoneM13a,
				task:      "SAFE-M13-09",
			},
			{
				area:      "CTRUST",
				point:     "the secret scan's matcher holds the device's compute credentials",
				pkg:       ".",
				tests:     []string{"TestComputeCustodyCredentialMatched"},
				milestone: computeMilestoneM13a,
				task:      "CTRUST-M13-01",
			},
		},
	},
}

// Whether name is one go test runs: Test, then nothing or a character no lowercase letter (go help testfunc).
func computeInvariantTestName(name string) bool {
	rest, ok := strings.CutPrefix(name, "Test")
	if !ok {
		return false
	}
	first, _ := utf8.DecodeRuneInString(rest)
	return rest == "" || !unicode.IsLower(first)
}

// What the check found over a matrix: a finding fails it, a pending line is logged.
type computeInvariantReport struct {
	findings []string
	pendings []string
}

// The top-level Test functions of the package in directory, by name: each _test.go file there parsed, none built. Not
// found, for a directory that does not exist; a finding for each file that does not parse, or a directory unread.
func computeInvariantPackageTests(directory string) (map[string]bool, bool, []string) {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, []string{fmt.Sprintf("%s: %v", directory, err)}
	}
	// func TestXxx(t *testing.T), with no receiver, type parameters or results: never a method, a subtest or TestMain
	isTest := func(function *ast.FuncDecl) bool {
		if function.Recv != nil || function.Type.TypeParams != nil || !computeInvariantTestName(function.Name.Name) {
			return false
		}
		if function.Type.Results != nil && 0 < len(function.Type.Results.List) {
			return false
		}
		params := function.Type.Params.List
		if len(params) != 1 || 1 < len(params[0].Names) {
			return false
		}
		star, ok := params[0].Type.(*ast.StarExpr)
		if !ok {
			return false
		}
		selector, ok := star.X.(*ast.SelectorExpr)
		return ok && selector.Sel.Name == "T"
	}
	tests := map[string]bool{}
	findings := []string{}
	fileSet := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		// go ignores a file whose name starts with . or _
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			continue
		}
		filePath := filepath.Join(directory, name)
		file, err := parser.ParseFile(fileSet, filePath, nil, parser.SkipObjectResolution)
		if err != nil {
			findings = append(findings, fmt.Sprintf("%s does not parse, and a broken file proves nothing: %v", filePath, err))
			continue
		}
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && isTest(function) {
				tests[function.Name.Name] = true
			}
		}
	}
	return tests, true, findings
}

// The matrix's tests over the module rooted at moduleRoot, landed the mark: each row at or before it must name tests
// that are top-level tests of its package, and each later row, and each in another repo, is logged.
func checkComputeInvariants(moduleRoot string, matrix []*computeInvariant, landed computeMilestone) *computeInvariantReport {
	report := &computeInvariantReport{}
	packageTests := map[string]map[string]bool{}
	packageFound := map[string]bool{}
	for _, invariant := range matrix {
		for _, row := range invariant.rows {
			if _, read := packageFound[row.pkg]; read || row.repo != "" {
				continue
			}
			tests, found, findings := computeInvariantPackageTests(filepath.Join(moduleRoot, filepath.FromSlash(row.pkg)))
			packageTests[row.pkg] = tests
			packageFound[row.pkg] = found
			report.findings = append(report.findings, findings...)
		}
	}
	for _, invariant := range matrix {
		for _, row := range invariant.rows {
			label := fmt.Sprintf("%s %s %s %s", invariant.id, row.area, row.task, row.milestone)
			state := "landed"
			if landed < row.milestone {
				state = "pending"
			}
			switch {
			case row.repo != "":
				report.pendings = append(report.pendings, fmt.Sprintf("%s %s, in %s's %s, not read here: %s", label, state, row.repo, row.pkg, strings.Join(row.tests, ", ")))
			case state == "pending" && len(row.tests) == 0:
				report.pendings = append(report.pendings, fmt.Sprintf("%s pending in %s: %s names its tests when it lands", label, row.pkg, row.task))
			case state == "pending":
				named := []string{}
				for _, test := range row.tests {
					presence := "absent"
					if packageTests[row.pkg][test] {
						presence = "present"
					}
					named = append(named, test+" ("+presence+")")
				}
				report.pendings = append(report.pendings, fmt.Sprintf("%s pending in %s: %s", label, row.pkg, strings.Join(named, ", ")))
			case len(row.tests) == 0:
				report.findings = append(report.findings, fmt.Sprintf("%s has landed and names no test", label))
			case !packageFound[row.pkg]:
				report.findings = append(report.findings, fmt.Sprintf("%s has landed, and its package %s does not exist", label, row.pkg))
			default:
				for _, test := range row.tests {
					if !packageTests[row.pkg][test] {
						report.findings = append(report.findings, fmt.Sprintf("%s has landed, and %s is no top-level test of package %s", label, test, row.pkg))
					}
				}
			}
		}
	}
	return report
}

// What is wrong with a matrix's shape: designIds is §2.4's ids in order, landed the mark.
func computeInvariantStructureFindings(matrix []*computeInvariant, designIds []string, landed computeMilestone) []string {
	findings := []string{}
	matrixIds := []string{}
	for _, invariant := range matrix {
		matrixIds = append(matrixIds, invariant.id)
	}
	if !slices.Equal(matrixIds, designIds) {
		findings = append(findings, fmt.Sprintf("the matrix holds %s where §2.4 holds %s, each once and in order", strings.Join(matrixIds, " "), strings.Join(designIds, " ")))
	}
	for _, invariant := range matrix {
		if invariant.summary == "" || strings.ContainsAny(invariant.summary, "\r\n") {
			findings = append(findings, fmt.Sprintf("%s needs a summary of one line", invariant.id))
		}
		if len(invariant.areas) == 0 {
			findings = append(findings, fmt.Sprintf("%s names no area", invariant.id))
		}
		for index, area := range invariant.areas {
			if !slices.Contains(computeInvariantAreaCodes, area) {
				findings = append(findings, fmt.Sprintf("%s names %s, no area of DESIGN-COMPUTE's", invariant.id, area))
			}
			if slices.Contains(invariant.areas[:index], area) {
				findings = append(findings, fmt.Sprintf("%s names %s twice", invariant.id, area))
			}
			if !slices.ContainsFunc(invariant.rows, func(row *computeInvariantRow) bool { return row.area == area }) {
				findings = append(findings, fmt.Sprintf("%s names %s and no row of it", invariant.id, area))
			}
		}
		if len(invariant.rows) == 0 {
			findings = append(findings, fmt.Sprintf("%s has no row", invariant.id))
		}
		for _, row := range invariant.rows {
			label := fmt.Sprintf("%s %s %s", invariant.id, row.area, row.task)
			if !slices.Contains(invariant.areas, row.area) {
				findings = append(findings, fmt.Sprintf("%s: a row may name only a test of an area its invariant lists", label))
			}
			if row.point == "" || strings.ContainsAny(row.point, "\r\n") {
				findings = append(findings, fmt.Sprintf("%s needs a point of one line", label))
			}
			if row.repo != "" && row.repo != computeInvariantRepoServer && row.repo != computeInvariantRepoSdk {
				findings = append(findings, fmt.Sprintf("%s: %q is no repo the matrix lists", label, row.repo))
			}
			if row.pkg == "" || path.IsAbs(row.pkg) || path.Clean(row.pkg) != row.pkg || strings.HasPrefix(row.pkg, "..") {
				findings = append(findings, fmt.Sprintf("%s: %q is no package directory of its module", label, row.pkg))
			}
			if row.milestone < computeMilestoneM11 || computeMilestoneM16 < row.milestone {
				findings = append(findings, fmt.Sprintf("%s: %s is no compute milestone", label, row.milestone))
			}
			if match := computeInvariantTaskPattern.FindStringSubmatch(row.task); match != nil {
				number, _ := strconv.Atoi(match[2])
				if match[1] != row.area || number != row.milestone.number() {
					findings = append(findings, fmt.Sprintf("%s: a task of %s at M%s owns no row of %s at %s", label, match[1], match[2], row.area, row.milestone))
				}
			} else if computeInvariantTrackAreas[row.task] != row.area {
				findings = append(findings, fmt.Sprintf("%s: %q is no plan task of %s, nor a track that owns its rows", label, row.task, row.area))
			}
			for index, test := range row.tests {
				if !computeInvariantTestName(test) {
					findings = append(findings, fmt.Sprintf("%s: %q is no name go test runs", label, test))
				}
				if slices.Contains(row.tests[:index], test) {
					findings = append(findings, fmt.Sprintf("%s names %s twice", label, test))
				}
			}
			if len(row.tests) == 0 && row.milestone <= landed {
				findings = append(findings, fmt.Sprintf("%s has landed at %s and names no test", label, row.milestone))
			}
		}
	}
	return findings
}

// Where DESIGN-COMPUTE.md is from this module's root: beside it, and one directory up on a release branch, whose module
// sits in v2026/ (§4.9), as protocol/design_fence_test.go's testComputeDesignPaths finds it.
var testComputeDesignRootPaths = []string{"DESIGN-COMPUTE.md", "../DESIGN-COMPUTE.md"}

// The lines of DESIGN-COMPUTE.md's section whose heading line is heading, up to the next heading of its level or
// above, a fenced block's lines never read as a heading.
func testComputeDesignSection(t testing.TB, heading string) []string {
	t.Helper()
	design, err := os.ReadFile(testComputeDesignRootPaths[0])
	if errors.Is(err, fs.ErrNotExist) {
		design, err = os.ReadFile(testComputeDesignRootPaths[1])
	}
	if err != nil {
		t.Fatalf("this test reads DESIGN-COMPUTE.md beside the module: %v", err)
	}
	lines := strings.Split(string(design), "\n")
	start := slices.Index(lines, heading)
	if start < 0 {
		t.Fatalf("DESIGN-COMPUTE.md has no line %q", heading)
	}
	level := len(heading) - len(strings.TrimLeft(heading, "#"))
	section := []string{}
	fenced := false
	for _, line := range lines[start+1:] {
		if strings.HasPrefix(line, "```") {
			fenced = !fenced
		}
		hashes := len(line) - len(strings.TrimLeft(line, "#"))
		if !fenced && 0 < hashes && hashes <= level && strings.HasPrefix(line[hashes:], " ") {
			break
		}
		section = append(section, line)
	}
	return section
}

// §2.4's invariant ids, in its order.
func testComputeDesignInvariantIds(t testing.TB) []string {
	t.Helper()
	pattern := regexp.MustCompile(`^- \*\*(IC-[0-9]+)\.\*\*`)
	ids := []string{}
	for _, line := range testComputeDesignSection(t, "### 2.4 Compute invariants") {
		if match := pattern.FindStringSubmatch(line); match != nil {
			ids = append(ids, match[1])
		}
	}
	if len(ids) == 0 {
		t.Fatal("§2.4 lists no invariant")
	}
	return ids
}

// Each of §2.4's invariants once and in order, each with its areas, a row for each area, and rows whose tests, tasks,
// milestones and packages are well formed.
func TestComputeInvariantsEachNamed(t *testing.T) {
	for _, finding := range computeInvariantStructureFindings(computeInvariantMatrix, testComputeDesignInvariantIds(t), computeInvariantsLanded) {
		t.Error(finding)
	}
}

// Each landed row's tests are top-level tests of their package, every package the matrix names parses, and each pending
// row is logged with its task.
func TestComputeInvariantTestsExist(t *testing.T) {
	report := checkComputeInvariants(".", computeInvariantMatrix, computeInvariantsLanded)
	for _, finding := range report.findings {
		t.Error(finding)
	}
	for _, pending := range report.pendings {
		t.Log(pending)
	}
	if len(report.findings) == 0 && len(report.pendings) == 0 {
		t.Error("the check read no row")
	}
}

// The checker over a temporary module fails with one named test missing and passes once it is there.
func TestComputeInvariantCheckerFindsMissing(t *testing.T) {
	root := t.TempDir()
	write := func(name string, text string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("probe/present_test.go", "package probe\n\nimport \"testing\"\n\nfunc TestPresent(t *testing.T) {}\n")
	matrix := []*computeInvariant{{
		id:    "IC-1",
		areas: []string{"CTRUST"},
		rows: []*computeInvariantRow{{
			area:      "CTRUST",
			pkg:       "probe",
			tests:     []string{"TestPresent", "TestMissing"},
			milestone: computeMilestoneM11,
			task:      "CTRUST-M11-02",
		}},
	}}

	report := checkComputeInvariants(root, matrix, computeMilestoneM11)
	if len(report.findings) != 1 || !strings.Contains(report.findings[0], "TestMissing") {
		t.Fatalf("missing: %q", report.findings)
	}
	if pending := checkComputeInvariants(root, matrix, computeMilestoneM10); len(pending.findings) != 0 || len(pending.pendings) != 1 || !strings.Contains(pending.pendings[0], "TestMissing (absent)") {
		t.Errorf("before the mark: %q, %q", pending.findings, pending.pendings)
	}

	write("probe/missing_test.go", "package probe\n\nimport \"testing\"\n\nfunc TestMissing(t *testing.T) {}\n")
	if report := checkComputeInvariants(root, matrix, computeMilestoneM11); len(report.findings) != 0 {
		t.Errorf("present: %q", report.findings)
	}
}

// Only a top-level test counts: never a subtest, a method, TestMain, a lowercase name or a function in a file go test
// does not build as a test; a file that does not parse fails the check whatever its rows; and a landed row's missing
// package fails while another repo's row is listed and not read.
func TestComputeInvariantCheckerCountsOnlyTopLevelTests(t *testing.T) {
	root := t.TempDir()
	write := func(name string, text string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("probe/probe_test.go", strings.Join([]string{
		"package probe",
		"import \"testing\"",
		"func TestOuter(t *testing.T) { t.Run(\"TestInner\", func(t *testing.T) {}) }",
		"type probeSuite struct{}",
		"func (probeSuite) TestMethod(t *testing.T) {}",
		"func TestMain(m *testing.M) {}",
		"func Testlowercase(t *testing.T) {}",
		"func TestTwoResults(t *testing.T) error { return nil }",
	}, "\n\n"))
	write("probe/probe.go", "package probe\n\nimport \"testing\"\n\nfunc TestInLibrary(t *testing.T) {}\n")
	write("probe/_ignored_test.go", "package probe\n\nimport \"testing\"\n\nfunc TestIgnored(t *testing.T) {}\n")
	rows := []*computeInvariantRow{}
	for _, test := range []string{"TestOuter", "TestInner", "TestMethod", "TestMain", "Testlowercase", "TestTwoResults", "TestInLibrary", "TestIgnored"} {
		rows = append(rows, &computeInvariantRow{area: "CTRUST", pkg: "probe", tests: []string{test}, milestone: computeMilestoneM11, task: "CTRUST-M11-02"})
	}
	rows = append(rows,
		&computeInvariantRow{area: "CTRUST", pkg: "absent", tests: []string{"TestAnything"}, milestone: computeMilestoneM11, task: "CTRUST-M11-02"},
		&computeInvariantRow{area: "CTRUST", repo: computeInvariantRepoServer, pkg: "computet3", tests: []string{"TestElsewhere"}, milestone: computeMilestoneM11, task: "CTRUST-M11-02"},
	)
	matrix := []*computeInvariant{{id: "IC-1", areas: []string{"CTRUST"}, rows: rows}}

	report := checkComputeInvariants(root, matrix, computeMilestoneM11)
	missing := []string{}
	for _, finding := range report.findings {
		for _, test := range []string{"TestOuter", "TestInner", "TestMethod", "TestMain", "Testlowercase", "TestTwoResults", "TestInLibrary", "TestIgnored", "TestAnything", "TestElsewhere"} {
			if strings.Contains(finding, " "+test+" ") {
				missing = append(missing, test)
			}
		}
		if strings.Contains(finding, "package absent does not exist") {
			missing = append(missing, "absent")
		}
	}
	slices.Sort(missing)
	want := []string{"TestIgnored", "TestInLibrary", "TestInner", "TestMain", "TestMethod", "TestTwoResults", "Testlowercase", "absent"}
	if !slices.Equal(missing, want) {
		t.Errorf("found missing %q, want %q, from %q", missing, want, report.findings)
	}
	if !slices.ContainsFunc(report.pendings, func(line string) bool { return strings.Contains(line, "not read here: TestElsewhere") }) {
		t.Errorf("another repo's row: %q", report.pendings)
	}

	write("probe/broken_test.go", "package probe\n\nfunc TestBroken(t *testing.T) {\n")
	pendingRows := []*computeInvariantRow{{area: "CTRUST", pkg: "probe", tests: []string{"TestOuter"}, milestone: computeMilestoneM12a, task: "CTRUST-M12-01"}}
	report = checkComputeInvariants(root, []*computeInvariant{{id: "IC-1", areas: []string{"CTRUST"}, rows: pendingRows}}, computeMilestoneM11)
	if len(report.findings) != 1 || !strings.Contains(report.findings[0], "broken_test.go does not parse") {
		t.Errorf("a broken file: %q", report.findings)
	}
}

// The structure check refuses each planted fault: an id out of §2.4's order, an area no row keeps, a row of an area its
// invariant does not list, a task of another area or milestone, a name go test does not run, and a landed row naming
// no test.
func TestComputeInvariantStructureRefusals(t *testing.T) {
	valid := func() []*computeInvariant {
		return []*computeInvariant{
			{
				id:      "IC-1",
				summary: "one",
				areas:   []string{"CTRUST"},
				rows:    []*computeInvariantRow{{area: "CTRUST", point: "a", pkg: ".", tests: []string{"TestA"}, milestone: computeMilestoneM11, task: "CTRUST-M11-02"}},
			},
			{
				id:      "IC-2",
				summary: "two",
				areas:   []string{"SUP"},
				rows:    []*computeInvariantRow{{area: "SUP", point: "b", pkg: "mcp", milestone: computeMilestoneM13b, task: "support-skill"}},
			},
		}
	}
	designIds := []string{"IC-1", "IC-2"}
	if findings := computeInvariantStructureFindings(valid(), designIds, computeMilestoneM11); len(findings) != 0 {
		t.Fatalf("a valid matrix: %q", findings)
	}
	type fault struct {
		plant func(matrix []*computeInvariant) []*computeInvariant
		find  string
	}
	faults := []fault{
		{plant: func(matrix []*computeInvariant) []*computeInvariant { return []*computeInvariant{matrix[1], matrix[0]} }, find: "each once and in order"},
		{plant: func(matrix []*computeInvariant) []*computeInvariant { return matrix[:1] }, find: "each once and in order"},
		{plant: func(matrix []*computeInvariant) []*computeInvariant {
			matrix[0].areas = append(matrix[0].areas, "INFER")
			return matrix
		}, find: "names INFER and no row of it"},
		{plant: func(matrix []*computeInvariant) []*computeInvariant {
			matrix[0].rows[0].area = "INFER"
			matrix[0].rows[0].task = "INFER-M11-03"
			return matrix
		}, find: "only a test of an area its invariant lists"},
		{plant: func(matrix []*computeInvariant) []*computeInvariant {
			matrix[0].rows[0].task = "CTRUST-M12-01"
			return matrix
		}, find: "owns no row"},
		{plant: func(matrix []*computeInvariant) []*computeInvariant {
			matrix[0].rows[0].task = "support-skill"
			return matrix
		}, find: "nor a track that owns its rows"},
		{plant: func(matrix []*computeInvariant) []*computeInvariant {
			matrix[0].rows[0].tests = []string{"Testa"}
			return matrix
		}, find: "no name go test runs"},
		{plant: func(matrix []*computeInvariant) []*computeInvariant {
			matrix[0].rows[0].tests = nil
			return matrix
		}, find: "names no test"},
		{plant: func(matrix []*computeInvariant) []*computeInvariant {
			matrix[1].rows[0].pkg = "../server"
			return matrix
		}, find: "no package directory"},
		{plant: func(matrix []*computeInvariant) []*computeInvariant {
			matrix[1].rows[0].milestone = computeMilestoneM10
			return matrix
		}, find: "no compute milestone"},
		{plant: func(matrix []*computeInvariant) []*computeInvariant {
			matrix[0].areas = []string{"CTRUST", "CTRUSTED"}
			return matrix
		}, find: "no area of DESIGN-COMPUTE's"},
	}
	for index, each := range faults {
		findings := computeInvariantStructureFindings(each.plant(valid()), designIds, computeMilestoneM11)
		if !slices.ContainsFunc(findings, func(finding string) bool { return strings.Contains(finding, each.find) }) {
			t.Errorf("fault %d: %q holds no %q", index, findings, each.find)
		}
	}
}
