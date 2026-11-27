//go:build !ios_extension

// DESIGN-COMPUTE §2.5's key custody table as data (CTRUST-M13-01): each key, its holder and who can misuse it, in
// §2.5's order, with where it is held as the daemon's matcher reads it. A row held on a device names the
// ComputeCustodyKind its owner registers (compute_custody.go), and RegisterComputeCustody takes no other kind; every
// other row says why no device registers it. TestComputeCustodyTableRows holds the table to §2.5's rows.

package sidecar

// Where one of §2.5's keys is held, as the daemon's matcher reads it.
type computeCustodyHolder int

const (
	// By a sidecar's daemon or app on a member's device, a tagged sidecar or an agents' enclave's incarnation, as a
	// compute credential: its owner registers it under the row's kind, so the matcher holds it.
	computeCustodyHeldOnDevice computeCustodyHolder = 1
	// Made in an enclave incarnation's VM and never leaving it: the incarnation's own sidecar keys, held as every
	// sidecar holds its own (DESIGN §16.6), the identity and client keys in its matcher already and an SSH host key
	// under ComputeCustodyKindSshKey on that incarnation.
	computeCustodyHeldInEnclave computeCustodyHolder = 2
	// In a provider's TEE: no device holds it.
	computeCustodyHeldByProvider computeCustodyHolder = 3
	// On the device only as a hash, so a leaked one is matched by its token form, the redactor's rule.
	computeCustodyHeldAsHash computeCustodyHolder = 4
	// Off the device: URnetwork's hosts, vault, the owners' hardware or a custodian.
	computeCustodyHeldOffDevice computeCustodyHolder = 5
)

// One row of §2.5.
type computeCustodyRow struct {
	// §2.5's first column: the key
	key string
	// words of §2.5's first column that find the row there
	designKey string
	// §2.5's second column: who holds it
	holder string
	// §2.5's third column: who can misuse it
	misuse string
	held   computeCustodyHolder
	// the kind its owner registers, for a row held on a device; zero otherwise
	kind ComputeCustodyKind
	// the area whose section designs its custody (DESIGN-COMPUTE's codes)
	area string
}

// §2.5's rows, in its order.
var computeCustodyTable = []*computeCustodyRow{
	{
		key:       "an enclave incarnation's identity, client, reader and SSH host keys",
		designKey: "An enclave incarnation's identity, client, reader and SSH host keys",
		holder:    "made in its VM at boot, bound in its evidence, never leaving it (§11.4)",
		misuse:    "the VM's software; its machine's holder by a physical attack, until the incarnation is revoked at its stop; with an agents' enclave's, everything its sponsor's devices read (CO-43)",
		held:      computeCustodyHeldInEnclave,
		area:      "ENC",
	},
	{
		key:       "the provisioning key of an incarnation",
		designKey: "The provisioning key of an incarnation",
		holder:    "made in the VM, bound in its evidence, erased after use",
		misuse:    "the VM",
		held:      computeCustodyHeldOnDevice,
		kind:      ComputeCustodyKindEnclaveProvisioningKey,
		area:      "ENC",
	},
	{
		key:       "an indexer enclave incarnation's mail-host key",
		designKey: "An indexer enclave incarnation's mail-host key",
		holder:    "made in its VM and attested by its identity key, as every receiver's is (DESIGN §13.8, §15.5), never leaving it (§11.10)",
		misuse:    "the VM's software; its machine's holder by a physical attack, until the incarnation is revoked",
		held:      computeCustodyHeldInEnclave,
		area:      "ENC",
	},
	{
		key:       "Chutes' instance E2E keys",
		designKey: "Chutes' instance E2E keys",
		holder:    "made in Chutes' TEEs",
		misuse:    "the TEE's software, the serving code included (§4.5)",
		held:      computeCustodyHeldByProvider,
		area:      "INFER",
	},
	{
		key:       "a device's SSH key",
		designKey: "A device's SSH key",
		holder:    "its keychain, registered with KeyRegister",
		misuse:    "as its identity key",
		held:      computeCustodyHeldOnDevice,
		kind:      ComputeCustodyKindSshKey,
		area:      "SSH",
	},
	{
		key:       "gateway tokens",
		designKey: "Gateway tokens",
		holder:    "the daemon's sealed store, as hashes, each with the harness process its mint showed, which makes it a run handle (§8.9); the harness's memory for an hour",
		misuse:    "same-user processes, within the grant's budget, and through a run handle only under its process's marks (§8.9)",
		held:      computeCustodyHeldAsHash,
		area:      "GW",
	},
	{
		key:       "a member's compute cache secret, S_m",
		designKey: "compute cache secret",
		holder:    "32 random bytes in an owner-bound secret repo of the member's, sealed again inside it to the ReaderKey of each of the member's consented devices, their agents' enclaves' among them, held by a daemon or an app alone; a tagged sidecar's own in its sealed state; the salts derived from it, in each run's recorded system text (§24.4)",
		misuse:    "those devices, which could probe the member's cache; a former device, until the new secret its leaving starts; whoever reads a run's recorded system text, until the next secret; never another member, a tagged sidecar or a Team's audit reader",
		held:      computeCustodyHeldOnDevice,
		kind:      ComputeCustodyKindCacheSecret,
		area:      "INFER",
	},
	{
		key:       "URnetwork's provider API keys",
		designKey: "provider API keys",
		holder:    "vault; the computeservice hosts",
		misuse:    "insiders; spends URnetwork's provider balances",
		held:      computeCustodyHeldOffDevice,
		area:      "PROV",
	},
	{
		key:       "API-key hotkeys K_P",
		designKey: "K_P",
		holder:    "a rate-limited signer on the computeservice hosts (§10.5)",
		misuse:    "insiders: at a gamma-native provider, URnetwork's whole account there",
		held:      computeCustodyHeldOffDevice,
		area:      "GAMMA",
	},
	{
		key:       "the compute mint coldkey",
		designKey: "compute mint coldkey",
		holder:    "vault; the taskworker hosts that mint",
		misuse:    "insiders: the mint float (2 days at most, bought just in time, §10.4)",
		held:      computeCustodyHeldOffDevice,
		area:      "GAMMA",
	},
	{
		key:       "the treasury reserve",
		designKey: "treasury reserve",
		holder:    "a 2-of-3 multisig on the owners' Ledgers",
		misuse:    "2 owners",
		held:      computeCustodyHeldOffDevice,
		area:      "GAMMA",
	},
	{
		key:       "the treasury's Prime account",
		designKey: "Prime account",
		holder:    "Coinbase Prime; its trading key in vault, on the taskworker hosts that mint; withdrawals whitelisted to the compute mint coldkey alone (§10.5)",
		misuse:    "insiders with the key or the exchange account, who can buy TAO with the week's USD and send it only to the mint coldkey",
		held:      computeCustodyHeldOffDevice,
		area:      "GAMMA",
	},
	{
		key:       "the compute-policy key; the staging key",
		designKey: "compute-policy key",
		holder:    "two of the compute-policy key's four holders sign, on hardware tokens, under the release key's certificate (DESIGN §2.6); the staging key on the CI host (§5.4)",
		misuse:    "two of its holders; the staging key's holder, whose policies only staging and CI builds verify",
		held:      computeCustodyHeldOffDevice,
		area:      "ATTEST",
	},
	{
		key:       "unreleased freshness tickets",
		designKey: "Unreleased freshness tickets",
		holder:    "a ticket host apart from the policy's serving path and the broker, which posts each on its day (§5.4)",
		misuse:    "whoever takes it and the serving path both: a revocation withheld up to 14 days",
		held:      computeCustodyHeldOffDevice,
		area:      "ATTEST",
	},
	{
		key:       "URnetwork's x402 payer key",
		designKey: "x402 payer key",
		holder:    "searchsigner, a rate-limited signer on hosts of its own, apart from computeservice's (§21.5)",
		misuse:    "insiders: the payer float, at most two days of searches",
		held:      computeCustodyHeldOffDevice,
		area:      "SRCH",
	},
	{
		key:       "the treasury's USDC",
		designKey: "treasury's USDC",
		holder:    "Coinbase, its withdrawals whitelisted to the payer address alone (§21.5)",
		misuse:    "insiders with the exchange account, who can send it only to the payer address",
		held:      computeCustodyHeldOffDevice,
		area:      "SRCH",
	},
	{
		key:       "a calendar link's secret",
		designKey: "calendar link's secret",
		holder:    "its member's secret repo (§23.6); a device's memory during one call; OAuth access tokens in memory, an hour at most",
		misuse:    "the member's consented devices, their agents' enclaves among them, each opening the copy sealed to it (§25.6); the provider that issued it",
		held:      computeCustodyHeldOnDevice,
		kind:      ComputeCustodyKindCalendarLinkSecret,
		area:      "MAILCAL",
	},
	{
		key:       "a connection's OAuth credentials",
		designKey: "connection's OAuth credentials",
		holder:    "its member's secret repo, one a connection; a device's memory during a refresh and its calls; access tokens in memory only, an hour at most",
		misuse:    "the member's consented devices that use them, their agents' enclaves among them, each opening the copy sealed to it, a Google token only its platform's (§25.6); the provider that issued them; each within the scopes granted",
		held:      computeCustodyHeldOnDevice,
		kind:      ComputeCustodyKindConnectionCredential,
		area:      "CONN",
	},
}
