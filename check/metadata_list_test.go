//go:build sidecar_check

// §22.7's list is generated: metadata_list.yml is §2.8's fenced block, byte for byte, comments
// included, so a row changes in the design and reaches the repository through make metadata. A hand
// edit here, or a design change that skipped make metadata, fails. sidecartest's strict reader reads
// the same bytes in go test ./..., and this package imports nothing of ours, so this reads only bytes.
//
// The one hand edit that passes is a line an owner's answer adds to the list ahead of design-records'
// fold of §2.8, named in metadataListAdditions with the question that holds the answer: the list is
// then §2.8's block with exactly those edits, byte for byte.

package check

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The list moves with the root module on a release branch, so it is relative to the module. design/
// stays at the repository's top, beside that module (§4.9), so the section is relative to the top.
const (
	metadataListFileName    = "metadata_list.yml"
	metadataListSectionPath = "design/source/sections/02-TRUST.md"
)

// What opens the block in §2.8, and what closes it.
const (
	metadataListHeading = "**The list**"
	metadataFenceOpen   = "```yaml"
	metadataFenceClose  = "```"
)

// The fenced block after §2.8's heading, without its fence lines, each line with its newline.
func metadataListBlock(section []byte) ([]byte, bool) {
	block := bytes.Buffer{}
	headingSeen := false
	fenceOpen := false
	for _, line := range bytes.SplitAfter(section, []byte("\n")) {
		text := strings.TrimSuffix(string(line), "\n")
		switch {
		case fenceOpen && text == metadataFenceClose:
			return block.Bytes(), true
		case fenceOpen:
			block.Write(line)
		case headingSeen && text == metadataFenceOpen:
			fenceOpen = true
		case strings.HasPrefix(text, metadataListHeading):
			headingSeen = true
		}
	}
	return nil, false
}

// Text an owner's answer adds to the list ahead of design-records' fold of §2.8: the block's text as the
// design writes it, which the block holds exactly once, the text the list holds in its place, and the
// question that holds the answer. Each applies to the block before the comparison, so the list stays
// exact in both directions: a list without the text fails, and so does an entry whose text the block no
// longer holds once, which is how one the design comes to write fails until its entry here leaves.
type metadataListAddition struct {
	question string
	block    string
	list     string
}

// Design-records wrote every entry before these into §2.8's block with the folds of 2026-11-16 (owner decision 252),
// QD-857's with §10's, QD-199's with §11's, QD-990's with §13's (owner decision 424), QD-996's with §20's, QD-1015's
// with the second fold of §7 (owner decision 557), QD-950's with the second fold of §11 (owner decision 408) and
// QD-1034's with the late sweep's (owner decision 592), QD-1137's, QD-1130's and QD-1154's with the fifth late
// sweep's (owner decisions 658, 656 and 655), QD-1165's with the fourth late fold's (owner decision 680), and
// QD-1186's with the sixth late fold's (owner decision 709); each here waits for the next fold.
var metadataListAdditions = []metadataListAddition{
	// DESIGN-COMPUTE.md's rows, ahead of design-records' fold of its Appendix D (CA-10, CA-52): the list's version,
	// the version's note, compute-1 to compute-11 after ext-15, each anchored on the row before it, and api-7's and
	// evs-1's amendments (CARCH-M11-03).
	{
		question: "DESIGN-COMPUTE.md §14.6 (CARCH-M11-03): the version",
		block:    "# metadata_list.yml v67;",
		list:     "# metadata_list.yml v68;",
	},
	{
		question: "DESIGN-COMPUTE.md §14.6 (CARCH-M11-03), QD-1252 and QD-1367: the version's note",
		block:    "# kept until the repo's shred; they show nothing the GroupForm chain does not, and no column, Redis family or\n# proto field changes.\n",
		list: "# kept until the repo's shred; they show nothing the GroupForm chain does not, and no column, Redis family or\n# proto field changes.\n" + `# v68, updated 2026-11-24 for DESIGN-COMPUTE.md §14.6 (CARCH-M11-03) and the owner's answers QD-1252 and QD-1367
# (compute-plan-money-schema-gaps, compute-plan-redis-family-rows), adds compute-1 to compute-11, the compute
# extension's rows, whose § are DESIGN-COMPUTE.md's: remote calls and their holds; lots, promotion codes, payers and
# the compute terms; charges and the account; enclaves; what the broker relays in transit; budgets; provider balances
# and gamma; disputes; collateral; and web searches and their outcome counts. It amends api-7 and evs-1 with the repo
# kinds agents and agent (DESIGN-COMPUTE §20.4) and listeners (§26.6), and api-7 with the projection's compute
# fields, ProjectionSettings.auth_features and {scf_<network_id>}, each sidecar's stated authorization features
# (§16.4, §16.6). Where §14.6 names no store or retention, a row states CARCH-M11-03's reading: the account under
# compute-3, the provider tables under compute-7, the terms kept for the network's life, and the budget counters,
# capacities and search counts kept as long as the period they count. compute-5 also lists what the broker carries to
# an enclave's VM, never stored (compute-plan-enc-readings, QD-1243).
`,
	},
	{
		question: "DESIGN-COMPUTE.md §14.6 (CARCH-M11-03): compute-1",
		block:    "  ttl: Microsoft's\n  owner: §21.5\n",
		list: "  ttl: Microsoft's\n  owner: §21.5\n" + `compute-1:
  service: compute (the broker, computeservice on server/cli/compute) and taskworker (compute_settle, compute_op_recover, compute_direct_settle, compute_rollup_day)
  store: compute_op, compute_charge (daily partitions) and compute_charge_day (MG-C1); Redis {cmp_<network_id>} (the holds and unsettled charges, each under its operation key), {cmpd_<k_p>} (direct calls in flight, nonce to hash and hold, and the nonces used in the last 15 seconds) and {cmpp_<k_p>} (direct calls pending while their provider's lookup fails, nonce to hold, no hash)
  sees: "per remote call: network, sidecar, opaque agent id, model id, provider, instance id, catalog version, declared token maxima, reported usage, request and response sizes (TEE path), start and end times (a direct call's kept to the minute once it settles, since its provider keeps its own), request id, outcome code, the route; a direct call's nonce and hash only until it settles (at most 10 minutes, in Redis, never in a log); its operation row until it is booked (DESIGN-COMPUTE §9.7): the hold, the budget reservation, the catalog version and price read it was admitted under, and a TEE call's instance and provider nonce, never a direct call's nonce or hash"
  why: a remote call's hold, settlement and charge, each from the row that admitted it, so no Redis key is the only record of a debt (DESIGN-COMPUTE §9.7, §14.4); disputes and the canary compare usage (§6.7)
  ttl: "holds in Redis at most 1 h, a pending direct hold at most 24 h; operation rows until booked and dropped, at most 24 h open; charge rows 90 days; daily rollups (no request ids, no instance ids) 400 days"
  owner: DESIGN-COMPUTE §14.6 (§9.7)
`,
	},
	{
		question: "DESIGN-COMPUTE.md §14.6 (CARCH-M11-03) and compute-plan-money-schema-gaps (QD-1252) and compute-plan-redis-family-rows (QD-1367): compute-2",
		block:    "  owner: DESIGN-COMPUTE §14.6 (§9.7)\n",
		list: "  owner: DESIGN-COMPUTE §14.6 (§9.7)\n" + `compute-2:
  service: api (the billing, promotion code and terms routes) and taskworker (compute_promo_lapse, compute_auto_renew)
  store: compute_lot, compute_promo_code, compute_promo_redemption, compute_payer, compute_payer_day and compute_terms (MG-C1); Redis {cmpk_<network_id>} (a network's failed promotion code redemptions this UTC day)
  sees: "per lot: network, kind, market, the market's reference, amounts, times, reversal or lapse, and a self-serve refund's amount (DESIGN-COMPUTE §9.12); per promotion code, a keyed hash of it, its campaign, value, cap, count, last day and who made it; per redemption, the code, the network, the lot, the redeeming sidecar's opaque id and the time; per payer, apart from any network: a keyed hash of a card's fingerprint or an App Store account's appTransactionId, its first purchase day and each day's sum (§9.11); per network, the compute terms' version and the clauses it accepted, with the accepting user and time (compute_terms, §21.9); a network's failed promotion code redemptions this UTC day (§9.11)"
  why: credits and what paid for them, refunds and reversals, promotion codes, and the payer limits that bound what a stolen card can buy (DESIGN-COMPUTE §9.4, §9.5, §9.11, §9.12); the web search clause the broker admits a search under (§21.9)
  ttl: "lots, promotion codes and redemptions 7 years (financial records); a payer's first day 2 years, its days 30 days; the compute terms' acceptances for the network's life, deleted with it; failed redemptions a network a UTC day, a day"
  owner: DESIGN-COMPUTE §14.6 (§9.4, §9.11, §21.9)
`,
	},
	{
		question: "DESIGN-COMPUTE.md §14.6 (CARCH-M11-03): compute-3",
		block:    "  owner: DESIGN-COMPUTE §14.6 (§9.4, §9.11, §21.9)\n",
		list: "  owner: DESIGN-COMPUTE §14.6 (§9.4, §9.11, §21.9)\n" + `compute-3:
  service: compute (the broker) and taskworker (compute_settle, compute_rollup_day); api (the charges, statement and spend routes)
  store: compute_charge (daily partitions), compute_charge_lot, compute_charge_day, compute_charge_total, compute_charge_pruned and compute_account (MG-C1)
  sees: "per charge: kind, subject ids, the member it counts to, model or shape, units, amount, cost and what URnetwork absorbed of it (DESIGN-COMPUTE §9.7), times; daily and monthly totals, a day's by sidecar, member, agent, model or shape, provider and enclave; lifetime totals by kind, member, model or shape, provider and enclave, with no day, sidecar or agent; per kind, the sums of day rows dropped past 400 days; and the network's first charge day (§9.13); per network, its account: the settled balance, its state (§9.9), the floor settlement may reach, the indexer enclave's reserve (§9.9) and any override of its search cap (§9.11)"
  why: statements, the spend view's totals and last 7 UTC days, refunds and the balance the states read (DESIGN-COMPUTE §9.4, §9.9, §9.13)
  ttl: "as compute-1; lifetime totals, the dropped rows' sums and the first charge day for the account's life, deleted with the network; the account for the network's life"
  owner: DESIGN-COMPUTE §14.6 (§9.4, §9.13)
`,
	},
	{
		question: "DESIGN-COMPUTE.md §14.6 (CARCH-M11-03): compute-4",
		block:    "  owner: DESIGN-COMPUTE §14.6 (§9.4, §9.13)\n",
		list: "  owner: DESIGN-COMPUTE §14.6 (§9.4, §9.13)\n" + `compute-4:
  service: compute (the orchestrator) and taskworker (compute_enclave_meter, compute_suspend)
  store: compute_enclave and compute_enclave_event (MG-C3); Redis {cmpe_<enclave_id>} (the orchestrator's lease and the nonces in flight)
  sees: "per enclave: id, network, sponsor sidecar, shape, provider, the provider's VM id, states and times, incarnations, the bootstrap hash, egress mode (already api-7's), its create's approval id and use (DESIGN-COMPUTE §16.3); whether it is the network's indexer, for its reserve and grace (§9.9)"
  why: enclave lifecycles, one owner per enclave, the meter and its holds (DESIGN-COMPUTE §11.6, §9.6, §14.2)
  ttl: "life + 90 days; the lease while its orchestrator renews it"
  owner: DESIGN-COMPUTE §14.6 (§11.6)
`,
	},
	{
		question: "DESIGN-COMPUTE.md §14.6 (CARCH-M11-03) and compute-plan-enc-readings (QD-1243): compute-5",
		block:    "  owner: DESIGN-COMPUTE §14.6 (§11.6)\n",
		list: "  owner: DESIGN-COMPUTE §14.6 (§11.6)\n" + `compute-5:
  service: compute (the broker's evidence tunnel and provisioning relay)
  store: memory only, in transit
  sees: "in transit only: evidence bytes, nonces, sealed provisioning bundles; for the tunnel, the host, sizes and times (its contents are the device's TLS, or its SSH at an enclave's setup); the bootstrap B the broker carries to an enclave's VM, which reads it from the host, and the per-VM token the VM uses from the host (DESIGN-COMPUTE §11.7, §14.3; QD-1243)"
  why: a device verifies a TEE's evidence and provisions an enclave itself, through the broker, which reads none of it (DESIGN-COMPUTE §5.7, §11.7)
  ttl: "not stored; relayed within 10 minutes; tunnel counts in metrics only"
  owner: DESIGN-COMPUTE §14.6 (§5.7, §11.7)
`,
	},
	{
		question: "DESIGN-COMPUTE.md §14.6 (CARCH-M11-03) and compute-plan-redis-family-rows (QD-1367): compute-6",
		block:    "  owner: DESIGN-COMPUTE §14.6 (§5.7, §11.7)\n",
		list: "  owner: DESIGN-COMPUTE §14.6 (§5.7, §11.7)\n" + `compute-6:
  service: compute (the broker) and api (the auto-renew and budget raise routes); taskworker (compute_auto_renew)
  store: compute_auto_renew and compute_budget_raise (MG-C1); Redis {cmp_<network_id>} (the projection's budget amounts by subject id) and {cmp_<network_id>}:b:<subject_id> (the budget counters, per day and month)
  sees: "auto-renew settings and budget amounts by subject id (from the projection), and each raise kind 21 approved, with its approval id and use (DESIGN-COMPUTE §16.3); what each subject's budgets have spent this UTC day and month (§16.4)"
  why: the budgets the broker holds every call to, whatever a device says, and the raises a person approved (DESIGN-COMPUTE §16.4); top-ups (§9.8)
  ttl: "while set; a raise until its expiry; a day's counters a day, a month's a month"
  owner: DESIGN-COMPUTE §14.6 (§16.4)
`,
	},
	{
		question: "DESIGN-COMPUTE.md §14.6 (CARCH-M11-03) and compute-plan-money-schema-gaps (QD-1252): compute-7",
		block:    "  owner: DESIGN-COMPUTE §14.6 (§16.4)\n",
		list: "  owner: DESIGN-COMPUTE §14.6 (§16.4)\n" + `compute-7:
  service: compute (K_P's signer) and taskworker (compute_gamma_mint, compute_gamma_spend, compute_gamma_watch, compute_provider_prices, compute_reconcile)
  store: compute_provider, compute_provider_price, compute_provider_ledger, compute_gamma_deposit and compute_gamma_op (MG-C2); Redis {cmpv_<provider_id>} (each provider's capacity)
  sees: "URnetwork's provider balances, gamma deposits, mints, spends and hotkeys (public on chain); per provider, its id, kind, status and gate results and its hourly price reads; and each provider's account as last read less the cost of what it served and the holds open there since, with no network (DESIGN-COMPUTE §10.4)"
  why: paying providers in gamma and holding no call or enclave past what a provider's account can serve (DESIGN-COMPUTE §10.4, §10.5, §10.7)
  ttl: "7 years; a capacity until the provider's next account read replaces it"
  owner: DESIGN-COMPUTE §14.6 (§10)
`,
	},
	{
		question: "DESIGN-COMPUTE.md §14.6 (CARCH-M11-03): compute-8",
		block:    "  owner: DESIGN-COMPUTE §14.6 (§10)\n",
		list: "  owner: DESIGN-COMPUTE §14.6 (§10)\n" + `compute-8:
  service: compute (the broker's dispute route)
  store: compute_dispute (MG-C1)
  sees: "disputes: request id, the device's and the provider's usage numbers"
  why: a charge the device's usage disagrees with is raised and judged (DESIGN-COMPUTE §6.7)
  ttl: 400 days
  owner: DESIGN-COMPUTE §14.6 (§6.7)
`,
	},
	{
		question: "DESIGN-COMPUTE.md §14.6 (CARCH-M11-03): compute-9",
		block:    "  owner: DESIGN-COMPUTE §14.6 (§6.7)\n",
		list: "  owner: DESIGN-COMPUTE §14.6 (§6.7)\n" + `compute-9:
  service: compute (the collateral cache)
  store: Redis {cmpc_<sha256>} (collateral items by hash)
  sees: "collateral items by hash (public vendor data); no requester"
  why: devices verify evidence against vendors' collateral without each asking the vendor (DESIGN-COMPUTE §5.7)
  ttl: each item's expiry
  owner: DESIGN-COMPUTE §14.6 (§5.7)
`,
	},
	{
		question: "DESIGN-COMPUTE.md §14.6 (CARCH-M11-03) and compute-plan-redis-family-rows (QD-1367): compute-10",
		block:    "  owner: DESIGN-COMPUTE §14.6 (§5.7)\n",
		list: "  owner: DESIGN-COMPUTE §14.6 (§5.7)\n" + `compute-10:
  service: compute (the broker's search admissions) and searchsigner (the payer key, apart, on hosts of its own); taskworker (compute_search_tickets, compute_search_purge)
  store: compute_op, compute_charge and compute_search_flag (MG-C1, MG-C2); Redis {cmpr_<network_id>} (a network's search rate and its searches today), {cmps} (the global search limiter, no network) and {cmpa} (open search admissions, on an instance of its own); the signer's search_signer_nonce, search_signer_day, search_signer_cursor, search_signer_facilitator and search_signer_screen (MG-S1, in its own database) and its own Redis
  sees: "per search: network, sidecar, opaque agent id, request id and attempt, authorization and settlement times to the minute, settled or lapsed, the charge, in its charge and operation rows (DESIGN-COMPUTE §9.7); the broker's ticket for it in memory until the signer reports, then only the answer it gave, with no network, an hour; the signer, apart, the authorization's nonce, payee and amount in memory until it settles or lapses on Base's finalized head, about 30 minutes, its issued nonces, with their values and windows and whether each settled and was attributed, and each UTC day's issued, settled, attributed and unattributed counts and values, all without a network; a sanctions record for a payee the screen refused or an authorization settled by a sender other than the facilitator: network, sidecar, payee, transaction and time (§21.5); a network's search rate and its searches this UTC day, against its day_max (§21.9); never the query, the mode or the results"
  why: a search's admission, hold and charge, paid by a one-search authorization no one system joins to its network (DESIGN-COMPUTE §21.5, D-CSRV-1); sanctions screening (§21.5)
  ttl: "per-search rows at most 72 hours, deleted from 71 h 55 min (§14.5), then compute-3's day rows; issued nonces a day past their window; the signer's day totals 7 years; sanctions records for OFAC's recordkeeping period, which counsel confirms; a network's searches today a day"
  owner: DESIGN-COMPUTE §14.6 (§21.5)
`,
	},
	{
		question: "DESIGN-COMPUTE.md §14.6 (CARCH-M11-03): compute-11",
		block:    "  owner: DESIGN-COMPUTE §14.6 (§21.5)\n",
		list: "  owner: DESIGN-COMPUTE §14.6 (§21.5)\n" + `compute-11:
  service: compute (the search authorize and outcomes routes) and taskworker (compute_search_outcomes)
  store: compute_search_outcome_hour (MG-C2); Redis {cmpo} (this hour's search outcome counts by class, across all networks)
  sees: "per search, its outcome class (ok, provider_error, timeout, refused), which a device reports with its next search authorization or in a daily count: seen with the reporting network only in transit, and added at once to an hourly count per class across all networks, never kept by network, sidecar or agent. New with CO-30: before it, the servers saw no search's outcome (DESIGN-COMPUTE §21.8)"
  why: Parallel's failure rate, which pages and which CO-30 asks the owner to watch (DESIGN-COMPUTE §21.8)
  ttl: the hourly counts 400 days; no report kept
  owner: DESIGN-COMPUTE §14.6 (§21.8)
`,
	},
	{
		question: "DESIGN-COMPUTE.md §14.6's api-7 (CARCH-M11-03): the repo kinds agents and agent (§20.4) and listeners (§26.6)",
		block:    "repos with kind, a general repo's group or admin inbox marker",
		list:     "repos with kind (agents, one a member, and agent, one an agent, so api sees how many agent repos a member has, DESIGN-COMPUTE §20.4; listeners, one a network, §26.6), a general repo's group or admin inbox marker",
	},
	{
		question: "DESIGN-COMPUTE.md §16.4, §16.6 and compute-plan-redis-family-rows (QD-1367): api-7's projection, its compute fields and auth_features",
		block:    "and their AclRows (has_document;",
		list:     "and their AclRows (has_document; the compute block's projected fields, its assurance floors, the providers allowed, the enclave shapes, budget amounts with their subjects and the search day cap, and ProjectionSettings.auth_features, the authorization features a head turns on (DESIGN-COMPUTE §16.4, §16.6);",
	},
	{
		question: "compute-plan-redis-family-rows (QD-1367): api-7's {scf_<network_id>}",
		block:    "re-seed uploads and the resumed marker; §7.9, QD-724)\n",
		list:     "re-seed uploads and the resumed marker; §7.9, QD-724); Redis {scf_<network_id>} (each sidecar's stated authorization features, from its core sync, unsigned, for the turn-on prompt alone; DESIGN-COMPUTE §16.6)\n",
	},
	{
		question: "compute-plan-redis-family-rows (QD-1367): {scf_<network_id>}'s retention, CARCH-M11-03's reading",
		block:    "its uploads dropped when the network's resume base lands\n",
		list:     "its uploads dropped when the network's resume base lands; {scf_} a sidecar's entry until its next core sync replaces it or its removal drops it\n",
	},
	{
		question: "DESIGN-COMPUTE.md §14.6's evs-1 (CARCH-M11-03): the repo kinds agents and agent (§20.4) and listeners (§26.6)",
		block:    "secret; directory, one per team network)",
		list:     "secret; directory, one per team network; agents, one a member, and agent, one an agent, DESIGN-COMPUTE §20.4; listeners, one a network, §26.6)",
	},
}

// §2.8's block with each addition in place, in order, and a finding for each that does not apply.
func applyMetadataListAdditions(block []byte, additions []metadataListAddition) ([]byte, []string) {
	findings := []string{}
	for _, addition := range additions {
		if addition.question == "" || addition.block == "" || addition.block == addition.list {
			findings = append(findings, findingf("the addition for question %q names no question or changes nothing", addition.question))
			continue
		}
		if count := bytes.Count(block, []byte(addition.block)); count != 1 {
			findings = append(findings, findingf("the addition for question %s no longer applies: §2.8's block holds its text %d times, not once; if the design now writes the line, its entry in metadataListAdditions leaves and make metadata brings the block here", addition.question, count))
			continue
		}
		block = bytes.Replace(block, []byte(addition.block), []byte(addition.list), 1)
	}
	return block, findings
}

// The first line two texts differ on, numbered from 1, for a finding a reader can act on.
func firstDifferentLine(a []byte, b []byte) int {
	aLines := bytes.Split(a, []byte("\n"))
	bLines := bytes.Split(b, []byte("\n"))
	for index := 0; index < len(aLines) && index < len(bLines); index += 1 {
		if !bytes.Equal(aLines[index], bLines[index]) {
			return index + 1
		}
	}
	return 1 + min(len(aLines), len(bLines))
}

// Whether the list in moduleDirectory is the block of §2.8 in topDirectory. The two are one directory
// in development and differ on a release branch.
func metadataListFindings(topDirectory string, moduleDirectory string) []string {
	return metadataListFindingsWithAdditions(topDirectory, moduleDirectory, nil)
}

// As metadataListFindings, the block first taking the additions.
func metadataListFindingsWithAdditions(topDirectory string, moduleDirectory string, additions []metadataListAddition) []string {
	section, err := os.ReadFile(filepath.Join(topDirectory, metadataListSectionPath))
	if err != nil {
		return []string{findingf("reading §2.8: %v", err)}
	}
	block, found := metadataListBlock(section)
	if !found {
		return []string{findingf("%s holds no fenced block under %s", metadataListSectionPath, metadataListHeading)}
	}
	list, err := os.ReadFile(filepath.Join(moduleDirectory, metadataListFileName))
	if err != nil {
		return []string{findingf("reading the list: %v; make metadata writes it", err)}
	}
	block, findings := applyMetadataListAdditions(block, additions)
	if 0 < len(findings) {
		return findings
	}
	if !bytes.Equal(list, block) {
		return []string{findingf("%s differs from §2.8's block at line %d: a row changes in the design, and make metadata brings it here", metadataListFileName, firstDifferentLine(list, block))}
	}
	return nil
}

func TestMetadataListIsSection2sBlock(t *testing.T) {
	repository := openThisCheckout(t)
	failFindings(t, "metadata list", metadataListFindingsWithAdditions(repository.topDirectory, repository.moduleDirectory, metadataListAdditions))
}

// An owner's answer ahead of the fold: the list holds the added text and the block does not yet.
func TestMetadataListPassesAnAdditionAheadOfTheFold(t *testing.T) {
	directory := plantMetadataList(t)
	additions := []metadataListAddition{{question: "a-question", block: "withdrawn: gone\n", list: "withdrawn: gone, and more\n"}}
	if err := os.WriteFile(filepath.Join(directory, metadataListFileName), []byte("# metadata_list.yml v1\nevs-1:\n  withdrawn: gone, and more\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	failFindings(t, "metadata list", metadataListFindingsWithAdditions(directory, directory, additions))
	// without its entry the same list is a hand edit
	wantFindings(t, metadataListFindings(directory, directory), "differs from §2.8's block at line 3")
}

// An entry is owed its text: a list still as the block writes it fails.
func TestMetadataListRefusesAListBehindItsAddition(t *testing.T) {
	directory := plantMetadataList(t)
	additions := []metadataListAddition{{question: "a-question", block: "withdrawn: gone\n", list: "withdrawn: gone, and more\n"}}
	wantFindings(t, metadataListFindingsWithAdditions(directory, directory, additions), "differs from §2.8's block at line 3")
}

// Once the design writes the line, or changes the text around it, the entry no longer applies and fails
// until it leaves.
func TestMetadataListRefusesAnAdditionTheBlockNoLongerHolds(t *testing.T) {
	directory := plantMetadataList(t)
	additions := []metadataListAddition{{question: "a-question", block: "withdrawn: went\n", list: "withdrawn: gone\n"}}
	wantFindings(t, metadataListFindingsWithAdditions(directory, directory, additions), "the addition for question a-question no longer applies")
}

// Text the block holds twice names no one place.
func TestMetadataListRefusesAnAdditionThatAppliesTwice(t *testing.T) {
	directory := plantMetadataList(t)
	additions := []metadataListAddition{{question: "a-question", block: "evs-1", list: "evs-2"}}
	section := "**The list**\n\n```yaml\n# metadata_list.yml v1\nevs-1:\n  withdrawn: see evs-1\n```\n"
	if err := os.WriteFile(filepath.Join(directory, metadataListSectionPath), []byte(section), 0o600); err != nil {
		t.Fatal(err)
	}
	wantFindings(t, metadataListFindingsWithAdditions(directory, directory, additions), "holds its text 2 times")
}

// An entry names its question and changes something.
func TestMetadataListRefusesAnEmptyAddition(t *testing.T) {
	directory := plantMetadataList(t)
	for _, addition := range []metadataListAddition{
		{block: "withdrawn: gone\n", list: "withdrawn: gone, and more\n"},
		{question: "a-question", list: "withdrawn: gone, and more\n"},
		{question: "a-question", block: "withdrawn: gone\n", list: "withdrawn: gone\n"},
	} {
		wantFindings(t, metadataListFindingsWithAdditions(directory, directory, []metadataListAddition{addition}), "names no question or changes nothing")
	}
}

// A module directory holding what make metadata reads, and a list it would write.
func plantMetadataList(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.MkdirAll(filepath.Join(directory, filepath.Dir(metadataListSectionPath)), 0o700); err != nil {
		t.Fatal(err)
	}
	section := "### 2.8\n\n```yaml\nnot: this block\n```\n\n**The list** (the only TTL table):\n\n```yaml\n# metadata_list.yml v1\nevs-1:\n  withdrawn: gone\n```\n\nAfter it.\n"
	if err := os.WriteFile(filepath.Join(directory, metadataListSectionPath), []byte(section), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, metadataListFileName), []byte("# metadata_list.yml v1\nevs-1:\n  withdrawn: gone\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestMetadataListPassesTheBlockItself(t *testing.T) {
	directory := plantMetadataList(t)
	failFindings(t, "metadata list", metadataListFindings(directory, directory))
}

// A release branch's shape: the section at the top, and the list one directory down in v2026/.
func TestMetadataListReadsTheSectionBesideAReleaseModule(t *testing.T) {
	topDirectory := plantMetadataList(t)
	moduleDirectory := filepath.Join(topDirectory, "v2026")
	if err := os.Mkdir(moduleDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(topDirectory, metadataListFileName), filepath.Join(moduleDirectory, metadataListFileName)); err != nil {
		t.Fatal(err)
	}
	failFindings(t, "metadata list", metadataListFindings(topDirectory, moduleDirectory))
	wantFindings(t, metadataListFindings(moduleDirectory, moduleDirectory), "reading §2.8")
}

func TestMetadataListRefusesAHandEdit(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.WriteFile(filepath.Join(directory, metadataListFileName), []byte("# metadata_list.yml v1\nevs-1:\n  withdrawn: edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantFindings(t, metadataListFindings(directory, directory), "differs from §2.8's block at line 3")
}

func TestMetadataListRefusesAnEditedComment(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.WriteFile(filepath.Join(directory, metadataListFileName), []byte("# metadata_list.yml v2\nevs-1:\n  withdrawn: gone\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantFindings(t, metadataListFindings(directory, directory), "differs from §2.8's block at line 1")
}

func TestMetadataListRefusesAMissingList(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.Remove(filepath.Join(directory, metadataListFileName)); err != nil {
		t.Fatal(err)
	}
	wantFindings(t, metadataListFindings(directory, directory), "make metadata writes it")
}

func TestMetadataListRefusesASectionWithNoBlock(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.WriteFile(filepath.Join(directory, metadataListSectionPath), []byte("### 2.8\n\nNo list here.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantFindings(t, metadataListFindings(directory, directory), "holds no fenced block")
}

// A block §2.8 opened and never closed is no block.
func TestMetadataListRefusesAnUnclosedBlock(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.WriteFile(filepath.Join(directory, metadataListSectionPath), []byte("**The list**\n\n```yaml\nevs-1:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantFindings(t, metadataListFindings(directory, directory), "holds no fenced block")
}

// The real Makefile on a planted section, so make metadata and this rule are shown to read one block.
func runMakeMetadata(t *testing.T, directory string) error {
	t.Helper()
	makefile, err := os.ReadFile(filepath.Join(openThisCheckout(t).moduleDirectory, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "Makefile"), makefile, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("make", "metadata")
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("%w\n%s", err, output)
	}
	return nil
}

func TestMakeMetadataRestoresAHandEdit(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.WriteFile(filepath.Join(directory, metadataListFileName), []byte("edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runMakeMetadata(t, directory); err != nil {
		t.Fatal(err)
	}
	failFindings(t, "metadata list", metadataListFindings(directory, directory))
}

// With no block to copy it fails, and an empty list never replaces a real one.
func TestMakeMetadataKeepsTheListWithoutABlock(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.WriteFile(filepath.Join(directory, metadataListSectionPath), []byte("### 2.8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runMakeMetadata(t, directory); err == nil {
		t.Errorf("make metadata succeeded with nothing to copy")
	}
	list, err := os.ReadFile(filepath.Join(directory, metadataListFileName))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) == 0 {
		t.Errorf("make metadata emptied the list")
	}
}
