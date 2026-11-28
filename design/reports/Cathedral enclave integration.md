# Cathedral Isn't a Version 1 Enclave: Its Rooms Take Commands and Can't Attest Themselves

> **The owner decided otherwise on 27 Nov 2026:** Cathedral enclaves ship at the merge as offered, with the exception and its disclosure recorded in "What the owner decided" at the end. The verdict in this title and the findings below are the evaluation's, kept as written.
>
> **Redacted for the public repository (2026-11-28, the owner's choice):** the dedicated host's name, its egress address and its hosting company are replaced with placeholders. The findings, the requirement table and the owner's decisions are unchanged.


Evaluation for UI-21. The owner, 27 November 2026: "Cathedral came back and gave us this integration guide: ~/urnetwork/factury/sidecar/URnetwork_Implementation_Guide.pdf . Incorporate this and see if we can include Cathedral in version 1 as another enclave optioon. I'd like to have more than one option."

**Cathedral can't be a user-facing enclave provider in version 1, and it can't pass G-PROV-cathedral on what the guide offers.** The guide (6 pages, "Prepared for URnetwork · 26 November 2026", open items as of 27 November) gives URnetwork a dedicated AMD SEV-SNP host, [the dedicated host], with root, `CAP_NET_ADMIN` and tun, images by digest, rooms that live until deleted, a 99.5% monthly SLA, and fresh attestation reports carrying 64 bytes the caller chooses. But each enclave would be a container ("room") inside the one SEV-SNP guest VM that every room on the host shares. No room can get a report of its own. And the same API that creates rooms runs commands in them: whoever holds URnetwork's account key can `exec` into any running room, and Cathedral's docs say its own "API and broker hold credentials that let them send their own requests to your room, encrypted or not, and the guest accepts them". That fails EPC-1 and EPC-2, which are what IC-3 rests on, and it runs into the owner directive's last line: "A server component that would see plaintext content is a design error and is never offered as an option." An agents' enclave holds its sponsor's whole vault (CO-43), so a broker that can run commands in one can read everything that person's devices hold.

**EPC headline: one item met (EPC-3, as claimed), four partly met (EPC-4, -5, -6, -7), three not met (EPC-1, -2, -8), one unknown (EPC-9).**

**Cathedral is worth keeping as the second option, and it could become the better one.** It answered each of URnetwork's questions in writing and set up a host for URnetwork alone with tun, root, rooms that live until deleted and caller-bound reports; it is the only chosen provider to have offered an SLA, and its own status table lists "Custom SNP VM / guest image: Pending … Need Ur imagine to sample" (p.1). If Cathedral gives each enclave its own SEV-SNP guest booting URnetwork's measured image, with `HOST_DATA` set to the bootstrap's hash, EPC-1, -2, -3 and -6 are met at once, §11.7 runs as written, and Cathedral could be the first enclave provider at A1 rather than AP. The fallback is sealed rooms that refuse every command for life plus a report a room can ask for itself, which keeps Cathedral at AP on a shared kernel. Either way it also needs E6 terms and gamma on the dedicated host's billing path.

**Version 1 can't carry user enclaves on any provider by a mid-December merge.** Beyond Cathedral's gaps, M14's platform isn't built (the repo has the agents' and edit containers and their socket; no SEV-SNP verifier, image pipeline, provisioning, orchestrator or SSH server yet), §19.4 puts enclaves about 3 to 5 months after a provider's written commitment, and the external audit of enclave provisioning, a gate for any user's enclave, isn't done. Hippius hasn't passed its gate either (DESIGN-UI's Q-UI-9 still lists its gaps). What version 1 can carry: the create sheet listing Hippius and Cathedral, each marked "Opens after its checks pass"; Cathedral's adapter as a draft; a staging pilot on [the dedicated host] with no user data; and the asks in 3.3, sent by the owner.

## 1. What the guide offers: a dedicated SEV-SNP host whose enclaves would be containers

### 1.1 Topic by topic

Quotes are the guide's, with its page. The third column adds what Cathedral's public pages and [the dedicated host]'s public binding said when fetched (28 November, about 02:00-02:30 UTC).

| Topic | The guide | Also true |
|---|---|---|
| TEE | "one reserved AMD SEV-SNP machine assigned to URnetwork" (p.1); "AMD EPYC Turin, DDR5, debug off" (p.2); `required_hardware: amd_sev_snp` "Requires SEV-SNP hardware." (p.2) | SEV-SNP only: Cathedral's Intel TDX service is retired and "New `custom.v1` orders are closed" (docs/api/sandboxes). Turin with DDR5 is within TEE.fail's reach (§2.6) |
| Tenancy | "Many rooms (sandboxes) share the host's single SEV-SNP guest VM." (p.1); "Single tenant: URnetwork is the only customer on this machine. Rooms share one SEV-SNP guest VM." (p.2) | "Rooms on the same hotel still share that guest and rely on the hotel's room runtime for separation"; "Treat two rooms on one confidential hotel as two containers on one attested machine"; "A TEE around a hotel does not make each room confidential from the other rooms on it" (docs/sandboxes/isolation). Several hotels can run on one physical chip, the signed-measurements page notes. The binding names no room runtime |
| Own code at launch | "Container image by digest: Yes. Specify on create." (p.1); "Custom container images referenced by digest are supported on create. Custom SNP VM or guest images are not." (p.3); `image` "Container image, by digest. Recorded in the receipt." (p.2). Custom guest image: "Pending. Container images only. Need Ur imagine to sample" (p.1), but "Not supported. Container images by digest are." and "Not available" (p.6) | Images are pulled at room start and are "**not** in that measurement" (docs/sandboxes/host-surface). What is measured is Cathedral's hotel image, and "The builds are not yet reproducible from source by anyone outside Cathedral" (signed-measurements) |
| `HOST_DATA` | "HOST_DATA bootstrap binding: Yes. Built" (p.1); "The HOST_DATA bootstrap binding has been built but is not yet bound on [the dedicated host]." (p.3); "For the HOST_DATA bootstrap, send Cathedral the owner public key and the SHA-256 of the bootstrap payload so they can be applied at the next dedicated re-seal." (p.3); "Not yet bound on [the dedicated host]." (p.6) | One value per host, set at a re-seal, which ends every room. The live binding already carries a `host_data` value (30b23fea…) and `"owner_gate": "open"`; neither is documented |
| Injection, SSH, metadata | "No. There is no SSH, cloud-init or metadata service, and environment variables are accepted only at creation. The host still supplies the clock, network addressing and disks." (p.4); `env_vars` "Configuration. Accepted at create only; there is no other injection path." (p.2) | Production builds reject "Unsolicited cloud-init / SSH authorized_keys from the host" (host-surface). "env values on create" travel on paths Cathedral's relays can read in plaintext (docs/sandboxes/what-cathedral-can-see) |
| Commands into a running room | "Create, exec, lifetime, usage, delete and sandbox attestation are served from api.polaris.computer." (p.1, p.2); `POST $BASE/v1/sandboxes/$ID/exec` (p.4, p.5) | Cathedral's "API and broker hold credentials that let them send their own requests to your room, encrypted or not, and the guest accepts them" (what-cathedral-can-see). Exec needs "a key with `sandboxes:control`" (docs/sandboxes/commands), the permission the docs also require for paid creates; no page offers a per-room way to refuse it. Background execs "are plaintext only" (docs/api/sealed-sandboxes) |
| Hotel attestation | "Fresh hotel report (POST attest): Yes. Caller-supplied 64-byte value." (p.1); `report_data_hex` "Your 64-byte value, hex encoded. Used on hotel and sandbox attestation." (p.3) | "REPORT_DATA is your 64 bytes as sent. It is not hashed"; `cert_chain` is null today, so the verifier fetches the VCEK from AMD's KDS (sealed-sandboxes) |
| How a guest gets its own report | "Sandbox attestation: Yes. api.polaris.computer only." (p.1); "Yes, through the API, at two levels: a fresh report for the hotel, and a report for an individual sandbox. Both take a caller-supplied 64-byte value. … There is no in-room /dev/sev-guest report yet. That is a follow-up and is not required to run on this host." (p.4); "In-room /dev/sev-guest report: Pending. Follow-up; not required to run on this host." (p.1); "Not shipped. No /dev/sev-guest device in rooms." (p.6); `report_data_mode: verbatim` "Sandbox attestation only" (p.3) | "No room has its own attestation"; "/dev/sev-guest is not exposed inside rooms, including on dedicated hotels" (isolation, host-surface). Modes are `bound` and `verbatim`; `bound`'s formula isn't documented, beyond "The API binds REPORT_DATA to the sandbox id". Cathedral's own caveat on its attestation: it "says nothing about the egress policy, the image, or who else is on the machine" (isolation) |
| Chip | `require_chip_id / prefer_chip_id` "Pins the physical chip (hard / soft)." (p.3); "Pin the physical chip at creation with require_chip_id, using the chip_id from the hotel binding." (p.4) | |
| Root and tun | "Root, CAP_NET_ADMIN, TUN: Yes. network_capability: tun with tenancy=dedicated." (p.1); "Is root, CAP_NET_ADMIN and /dev/net/tun available? Yes. … TUN works only with tenancy=dedicated; the shared pool refuses it with HTTP 422." (p.4) | For tun, "The hotel's egress policy still applies" (host-surface). A room may run "a privileged Docker-in-Docker image" (isolation). A tun room's capabilities and seccomp profile aren't documented |
| Egress | "Egress: [its egress address] (UDP open under network internet; no IPv6)" (p.2); `network: internet` "Egress. UDP is open; IPv6 is not available." (p.2) | UDP under `internet`: "Intended yes for customer tunnels - treat as needs live proof until a canary stamps PASS"; IPv6 isn't a product commitment for dedicated or tun hosts in this release; the other modes are `deny_all` (default) and `allowlist` (1 to 32 IPv4 hosts) (docs/sandboxes/egress-matrix). The address sits in a /24 announced by AS204770, [a bare-metal hosting company] (UAB "[a bare-metal hosting company]", Lithuania, a bare-metal host), whose holder isn't published (RIPE whois) |
| Lifecycle | "POST /v1/sandboxes on api.polaris.computer accepts the fields below. Send Authorization, Content-Type: application/json and a unique Idempotency-Key on create, lifetime and delete calls." (p.2); `lifetime_policy: until_delete` "Room stays until deleted. Extend with /lifetime." (p.2); "The room is not a separate VM and ends if the host restarts." (p.4); "There is no /renew route; use /lifetime." (p.5); usage and delete calls (p.5) | Status by `GET /v1/sandboxes/{id}`; a room also ends at its spend cap: it runs "until you delete it, until its stop time, or until its spend cap" (docs/sandboxes/persistent) |
| Billing and payment | `template` "Rates: 1/2 USD 0.005, 2/4 USD 0.01, 4/8 USD 0.02, 8/16 USD 0.04 per hour." (p.2); `max_spend_usd` "Spend cap for the sandbox." (p.3); the key is "A normal Cathedral account key, applied once the host is assigned to that account. It works the same way as any other client's key." (p.2). Nothing on gamma, invoices or the host's own price | Billed per second (docs/pricing). "Paid work needs prepaid USD credit": card, USDC or TAO, $20 to $10,000 a payment (docs/api/account). Gamma pays btauth/1 routes "signed by that hotkey, with no sign-up or API key" (cathedral.computer/v1/gamma/services.json). Reserved hotels: 160 rooms of 1 vCPU and 4 GiB for about $1,168 a month, billed monthly on what is reserved once confirmed (account); dedicated attestation "is included with the dedicated add-on" (isolation) |
| SLA | "99.5% monthly on the dedicated host" (p.2) | The public terms (13 November 2026) promise no service level: "Features and availability may change." |
| Region | only the host id, [the dedicated host]; no region is named | one host; its egress is on [a bare-metal hosting company]' network |
| Limits | "resources.disk_gib: 10 is required on create today, until the host disk budget is raised." (p.2, p.6) | no template above 8 vCPU and 16 GiB; 50 GiB is the default disk elsewhere; a foreground exec waits up to 45 seconds (docs/sandboxes/limits, docs/pricing) |
| Terms | none | "operated by Polaris Cloud LLC"; no DPA, no resale or no-training clause, no notice before suspension; liability capped at what was paid in the three months before (cathedral.computer/terms) |
| Credentials | a live dedicated key on p.1; "Handle the key as a password. If it is leaked, or you want it rotated, email" Cathedral's support (p.2) | |

### 1.2 What [the dedicated host]'s public binding shows

`GET https://cathedral.computer/v1/hotels/[the dedicated host]/attestation`, the guide's own first quick-start check (p.5), needs no key. It returned:

- `"tenancy": "dedicated"` and `"measurement": "d855c640…"`, matching the guide. The signed release (number 36, generated 2026-11-27 17:03:40 UTC) lists two measurements for [the dedicated host], 91ae30c0… and d855c640…, as a hotel being rolled to a new build does.
- `"created_at"`: 2026-11-27 21:49:42 UTC. The host's current boot began about four and a half hours before this was read, so it was re-sealed after the guide's date, and any room created before then has ended.
- `"policy": "0x30000"`: debug off and no migration agent, as §5.3 requires; SMT allowed (§5.3 records it). `PAGE_SWAP_DISABLE` and ciphertext hiding are off; §5.3 asks for `PAGE_SWAP_DISABLE` where the platform reports it, which only the report's platform info shows.
- `"reported_tcb": "0103030800000076"`. Read in Turin's layout, SNP firmware is 0x08, §5.3's floor for 9005 parts. The live test must confirm it against the VCEK certificate's own TCB, since Cathedral's docs say "Clients do not yet enforce a minimum AMD firmware (TCB) version."
- `"chip_id": "8da577edcb99abd7"` followed by zeros, the 8-byte identity Turin parts report.
- `"kernel_release": "7.0.0-14-generic"` and a command line with `console=ttyS0 loglevel=7`, so kernel messages go to a serial console the host reads. Whether a login runs there isn't stated; EPC-1 requires "no login on any console (serial, virtual or vsock)".
- `"hotel_key_source": "install"`, with an install signer and an install X25519 key, and keys for Cathedral's own encrypted exec and secrets to the hotel. Cathedral's docs say the hotel's API key is made inside the guest and "The host never holds it"; what "install" means needs Cathedral's answer.
- `"host_data": "30b23fea…"` and `"owner_gate": "open"`, both undocumented.

### 1.3 How this was checked, and what was left alone

- **The key.** Page 1 prints a live bearer key for URnetwork's Cathedral account. It isn't reproduced here, since this repo is public. It can create rooms and run commands in them, so it belongs in vault and should be rotated, as the guide allows (p.2), since it traveled in a PDF.
- **No contact.** Nothing here used the key or called Cathedral's authenticated API. The only Cathedral addresses read were public documentation pages, the public measurement lists, the gamma service document, the terms, and the binding above. The egress address was looked up in RIPE's whois.
- **Text aimed at agents.** The guide has none. Cathedral's site has some, which was read as data and not followed: the home page says "Read cathedral.computer/agents.md" and "For agents. One paste, and it asks before it spends.", and the account docs say "An agent cannot pay: on `402 insufficient_credits` nothing was created, so stop and ask your person to add credit."
- **The guide against itself.** p.1 says `HOST_DATA` binding "Yes, Built", p.3 and p.6 say "not yet bound". p.1 says a custom guest image is "Pending" with a request for our image, p.6 "Not available". p.2 puts the live measurement "on the signed list at /approved-measurements.json"; that file is Cathedral's earlier unsigned list, and the signed release is `/approved-measurements.signed.json`, signed by an Ed25519 key Cathedral calls "a local interim key, held encrypted on a Cathedral operations server", of which "anyone with root on that server can sign with it".

## 2. Against the enclave platform contract: one met, four partly, three failed, one unknown

| Item | Status | Evidence (guide page, or source) | What would close it |
|---|---|---|---|
| EPC-1 Measured payload | **Not met** | None of the four forms is offered. Our image as the guest: "Custom SNP VM or guest images are not" (p.3), "Not available" (p.6), though p.1 says "Pending … Need Ur imagine to sample". The room's image is recorded in a receipt (p.2) but is "not in that measurement" (host-surface). `HOST_DATA` is "not yet bound" (p.3, p.6) and is one value per host, set at a re-seal. "There is no SSH" (p.4), so there is no setup over SSH. And the rule every form shares fails: exec reaches running rooms through the API (p.1, p.4, p.5), and Cathedral's API and broker can send requests the guest accepts (what-cathedral-can-see) | Path A: a guest per enclave booting `ur-enclave` with `HOST_DATA` = SHA-256(B), or Path B: sealed rooms plus a report binding the room's image (4.1) |
| EPC-2 Guest attestation | **Not met** | "There is no in-room /dev/sev-guest report yet" (p.4); "No /dev/sev-guest device in rooms" (p.6). Reports come only through the API, carrying "a caller-supplied 64-byte value" (p.1, p.4): fresh, but chosen outside the room, so they can't show that a key was made inside it | Path A, or an in-room report (Ask 3) |
| EPC-3 Root | **Met, as claimed** | "Root, CAP_NET_ADMIN, TUN: Yes" (p.1); "Is root, CAP_NET_ADMIN and /dev/net/tun available? Yes." (p.4). It is a container's root on the hotel's shared kernel; whether §11.10's agents' container and nftables rules run inside a room is untested | live test; Ask 5 |
| EPC-4 Outbound | **Partly met** | "[its egress address] (UDP open under network internet; no IPv6)" (p.2). TCP over IPv4: yes. UDP: claimed, but Cathedral's own matrix says "treat as needs live proof". No IPv6, which `ur tun` carries to exits anyway. Inbound isn't needed | a live UDP test with connect's transports; Ask 12 |
| EPC-5 Lifecycle | **Partly met** | Create by digest, usage, lifetime and delete with idempotency keys (p.2-p.5); status by `GET` and per-second billing (docs). No per-enclave launch data: only `env_vars`, which pass Cathedral's API in plaintext (p.2; what-cathedral-can-see). Rooms end "if the host restarts" (p.1, p.4) and at their spend cap (persistent) | per-enclave `HOST_DATA` (Path A) or the in-room binding (Path B); a way to raise a running room's cap; re-seal notice |
| EPC-6 Single tenant | **Partly met** | No other Cathedral customer: "URnetwork is the only customer on this machine" (p.2). But "Rooms share one SEV-SNP guest VM" (p.2), so every network's enclaves on [the dedicated host] would share one guest and kernel, kept apart by Cathedral's container runtime: the layout §11.14 rejected ("A container per enclave on a shared confidential VM … other tenants in the VM (EPC-6)") | Path A, or one network per guest (Q-CATH-3) |
| EPC-7 Gamma | **Partly met** | SN94 has gamma on (since 16 November, [Rpt:bt]) and Cathedral's service document takes btauth/1 on "every paid route". But the dedicated host is reached with "a normal Cathedral account key" (p.2), funded with "prepaid USD credit" by card, USDC or TAO (account), and the guide never mentions gamma | gamma for the dedicated host (Ask 7) |
| EPC-8 Terms | **Not met** | No terms in the guide. The public terms have no DPA, resale, no-training or notice-before-suspension clause, and say "Features and availability may change." The SLA (p.2) helps but isn't an agreement | a signed agreement (Ask 8) |
| EPC-9 Kernel | **Unknown** | The guest kernel is Cathedral's, "7.0.0-14-generic" in the live binding; no patch cadence is stated anywhere; the builds aren't reproducible outside Cathedral; each new build is a re-seal, which ends every room (p.4) | a written cadence (Ask 9), or Path A, where the kernel is `ur-enclave`'s |

The two failures that matter most are EPC-1 and EPC-2: together they are what IC-3 rests on. With neither, a device can't tell a key made in the room from one the broker or Cathedral presents, and nothing stops either from entering the room after the device has checked it.

## 3. Where G-PROV-cathedral stands

§4.7's gate: "as Hippius: general availability; EPC-1 to EPC-9 (§11.3), by setup over SSH's one feature (Q-ENC-7) if not by launch data; how a guest requests its own report, and the image's measurements, documented; SN94's gamma service credits a test hotkey; E6". "As Hippius" adds §18's tests run on the provider itself, a placement the broker doesn't choose for the indexer, and the external audit of §11.7 and §12.

| Condition | Status |
|---|---|
| General availability | Not met: the home page still says "Sign-in is unavailable on this preview." The guide calls [the dedicated host] "live" (p.1) and gives it an SLA (p.2); Q-CATH-4 proposes a signed agreement in GA's place |
| EPC-1 to EPC-9 | Not met: section 2 |
| Setup over SSH's one feature | Not offered: "There is no SSH, cloud-init or metadata service" (p.4) |
| Launch data | Not per enclave: per host, at a re-seal, not yet bound (p.3, p.6) |
| How a guest requests its own report, documented | Not met: there is no in-room report (p.4, p.6) |
| The image's measurements, documented | Partly: [the dedicated host]'s measurements are published and signed, under an interim key; not reproducible outside Cathedral, so a profile would enter the policy as `listed`, not `reproduced` (§5.4) |
| SN94's gamma credits a test hotkey | Untested; and gamma doesn't reach the dedicated host's account today |
| E6 | Not met |
| §18's tests on Cathedral itself | Not run; most can't pass until the asks below land |
| Indexer placement | Could pass: one dedicated host whose chip the signed policy pins (`require_chip_id`, p.3, p.4) is a machine the broker can't choose. Q-CATH-9 decides it |
| External audit of §11.7 and §12 | Not done (§19.2) |

### 3.1 What the guide alone establishes

As Cathedral's statements, with the public binding confirming the first three: [the dedicated host] is SEV-SNP on Turin with debug off; it is dedicated to URnetwork's account; its measurement is d855c640…; a fresh hotel report can carry our nonce, which proves the hotel is live and measured, though not who holds a key; a room can be created by image digest with root, `CAP_NET_ADMIN` and tun, live until deleted; the chip can be pinned; the host promises 99.5% a month; prices run from $0.005 to $0.04 an hour by size.

### 3.2 What needs a live test on [the dedicated host]

Run in staging with test data only (§11.3's pilot rule; D-CPHASE-4), with the key from vault, by URnetwork's engineers:

1. The guide's quick start (p.5), recorded as §18's attestation vectors for Cathedral: the hotel report with our nonce verified by the device's SEV-SNP checks (VCEK from KDS, TCB against the VCEK, policy bits, platform info, measurement, chip id), plus negative vectors.
2. Room lifetimes and restarts measured over at least two weeks (D-CPHASE-4): how often the host re-seals, with what notice, and how long a restart takes.
3. Tun and egress: `ur tun` up in a room, each egress mode with fail-closed nftables rules in the room's namespace (§18's Enclaves row), UDP with connect's transports, and outbound 25 refused by our rules.
4. Inside a room: whether systemd-nspawn can make the agents' container with its own user, PID, mount and network namespaces (§11.10), and whether device-mapper works for §11.9's scratch volume. If nspawn can't run, IC-14's boundary can't be built in a room.
5. Once Ask 2 and Ask 3 land (Path B), or Ask 1 (Path A): §18's "a rewritten bootstrap bundle refused by init"; a command, file or snapshot sent by URnetwork's own account key refused by a sealed room; step 5's evidence from a second room of the same image refused; and the attach's session binding (§12.6).
6. Gamma: mint SN94 gamma, spend it at Cathedral's service hotkey, see it credited, and pay for a room on the dedicated host with it.

### 3.3 What Cathedral would have to confirm or change

These are for the owner to send; nothing here was sent. Ask 1 is the target, Asks 2 and 3 the bridge.

1. **A guest per enclave** (Path A). One SEV-SNP VM per enclave on the dedicated host, booting URnetwork's `ur-enclave` image measured at launch (EPC-1's first form), `HOST_DATA` set per VM to SHA-256(B), Cathedral's guest firmware and VM layout published so the device's profile can be computed, `/dev/sev-guest` in the guest, and no Cathedral agent, exec path or console login inside. The guide's "Need Ur imagine to sample" (p.1) invites this; the image is M14 work and doesn't exist yet.
2. **Sealed rooms** (Path B). A create flag after which the hotel refuses, for the room's whole life and from every caller, Cathedral's own API and broker included: exec, background execs, file transfers, processes, the console, port URLs, snapshots and forks. The flag belongs in the room's attested config.
3. **An in-room report** (Path B). An endpoint only the room can reach (a socket mounted into it, or vsock), through which code in the room asks the hotel for a fresh SNP report whose report data Cathedral defines and documents as a hash over a domain string, the sandbox id, the image's manifest digest, the hash of the room's config and 64 bytes the room chose, returned with that config.
4. **What the binding means.** `bound` mode's formula; what `host_data` commits to today; what the `HOST_DATA` bootstrap's "owner public key" would authorize, and whether it opens any way into a guest; what `owner_gate` and `"hotel_key_source": "install"` mean; that the hotel's own keys are made in the guest.
5. **The room runtime.** Which runtime [the dedicated host] runs (`docker`, `runsc` or `kata`), named in the binding; the capabilities, seccomp profile and devices a tun room gets; whether a room may create user, mount and network namespaces.
6. **The machine.** That no other hotel runs on [the dedicated host]'s chip, since Cathedral's docs say several hotels can run on one; who physically holds the machine, and where.
7. **Gamma.** btauth/1 under URnetwork's hotkey on the dedicated routes, or SN94 gamma spends credited to the account holding [the dedicated host]; how the dedicated host itself is billed (per room-second, or a monthly reservation like the docs' hotel at about $1,168 a month); a route to raise a running room's spend cap, or no cap on dedicated rooms.
8. **E6 in writing.** Rental on behalf of URnetwork's users, a DPA, no training on anything in a room, notice before suspension, the 99.5% SLA, and notice before any re-seal or planned restart.
9. **EPC-9.** Kernel security fixes within 14 days of release, each as a new signed measurement; the measurement key moved off the operations server, as Cathedral's docs plan; reproducible builds or a published recipe.
10. **Disk and sizes.** At least 64 GiB of disk a room (128 and 256 for larger shapes) in place of today's 10, and a template with 8 GiB of memory for 2 vCPU if possible.
11. **The serial console.** That no getty or login runs on `ttyS0`, and a lower console log level than `loglevel=7`.
12. **UDP.** The canary result for UDP under `internet` on dedicated tun hosts.
13. **The key.** Rotation of the key the guide carried.

## 4. Integration design, proposed

### 4.1 Two ways in

| | Path A: a guest per enclave | Path B: sealed rooms |
|---|---|---|
| Cathedral changes | Ask 1, then 6 to 13 | Asks 2 to 5, then 6 to 13 |
| URnetwork builds | the adapter and Cathedral's measurement profile for `ur-enclave`; §11.7 runs as written (EPC-1's first form) | the adapter, a room build of `ur-enclave` (an OCI image whose init needs no device-mapper), the `cathedral-room-v1` check (4.3), and the agents' container only if a room allows its namespaces |
| EPC | 1, 2, 3 and 6 met by the form; 9 is `ur-enclave`'s own cadence | 1 and 2 met by Cathedral's measured hotel acting for the room; 6 met only with one network per guest |
| Label | A1 if the gate shows nothing of Cathedral's runs in the guest and the profile is `reproduced`; AP otherwise | AP: Cathedral's hotel image, its signing key and its room runtime sit inside the boundary |
| Indexer | yes, on the pinned chip | only on a guest that holds no agents' enclaves (Q-CATH-9) |

Path A is the one to ask for first. It costs URnetwork the least, needs no new binding scheme, and is the only path on which Cathedral could be better than Hippius rather than equal to it.

### 4.2 The adapter

`computeservice`'s `cathedral` provider (slug and code 6 already in `computeservice/provider.go`), with a device half beside `enclave_provider.go`:

- **Where it points.** API base `https://api.polaris.computer`, public base `https://cathedral.computer`. The dedicated host's id and its chip id come from the signed policy (§5.4), not from the adapter's settings, so a breached broker can't move enclaves to another hotel.
- **`CreateVm`.** `POST /v1/sandboxes` with `Idempotency-Key` = SHA-256 of the enclave id and incarnation number, so a retried call never makes two rooms; `required_hardware: amd_sev_snp`; `template` from the shape (below); `image` = the digest the policy pins for B's image version; `tenancy: dedicated`, `dedicated_hotel` and `require_chip_id` from the policy; `network: internet`, `network_capability: tun`, `lifetime_policy: until_delete`; `resources.disk_gib` per shape; `max_spend_usd` at 30 days of the shape's price (Ask 7 for raising it); the sealed flag (Ask 2). `env_vars` carry only the per-VM token (§14.3); the room's init fetches B from the broker with it, so B's network id and sidecar id never cross Cathedral's API, which reads env values in plaintext. No labels, names or network ids are sent. Under Path A the create names our image and `HOST_DATA` = SHA-256(B) in whatever form Cathedral's VM API takes.
- **`VmStatus`.** `GET /v1/sandboxes/{id}`, mapped to the adapter's VM states; a room ended by a host restart is `ComputeVmLost` (§11.11), which needs Cathedral to report that reason.
- **`VmEvidence`.** Not the trust path: the room's own evidence reaches the device through the broker (§11.7 step 5), and the device never takes the API's report in its place. The adapter may record a hotel report with the device's nonce beside it.
- **`DeleteVm`.** `DELETE /v1/sandboxes/{id}` with an idempotency key; 404 counts as done.
- **`Catalog`.** Shapes mapped to Cathedral's templates (Q-CATH-7): `cpu-2` to `sealed-4x8` (4 vCPU, 8 GiB), `cpu-4` to `sealed-8x16`, no `cpu-8`; prices read hourly from Cathedral's pricing route; capacity from the hotel.
- **`Payment` and `Balance`.** Gamma on netuid 94 (configuration, D-PROV-4), Cathedral's service hotkey from its service document, URnetwork's K_P; the balance from Cathedral's gamma balance route or the account's credit.
- **Reconciliation.** Every poll lists the account's rooms against `compute_enclave` and pages on a room URnetwork didn't create (§10.5). On a shared guest, an unknown room is a co-tenant that could attack every enclave there.
- **Errors.** `402 insufficient_credits` and sold out answer `capacity` and page; `422 tun_requires_dedicated` is a configuration fault.

### 4.3 The check a member's device runs before sealing keys (IC-3)

**Path A** is §11.7 step 6 as written, for SEV-SNP: AMD's chain from the VCEK, fetched for the report's chip id and TCB through the collateral cache, to the pinned Turin ARK; the TCB checked against the VCEK's own extensions and the policy's floor; `DEBUG` 0, `MIGRATE_MA` 0, SMT reported, `PAGE_SWAP_DISABLE` where platform info offers it; `MEASUREMENT` equal to `ur-enclave`'s profile under Cathedral's firmware and VM layout; `HOST_DATA` = SHA-256(B); `CHIP_ID` equal to the policy's pin for the dedicated host; report data = `ur-enclave-v1` over the device's nonce, SHA-256(B) and H. Only then does the device seal to P.

**Path B** adds a scheme. Proposed row for §5.5:

| Scheme | Used by | Report data | The key bound |
|---|---|---|---|
| `cathedral-room-v1` | enclaves in a sealed Cathedral room | 64 bytes the hotel computes as Cathedral documents it (Ask 3), expected `SHA-512("cathedral-room-report-v1" ‖ 0x00 ‖ sandbox id ‖ image manifest digest ‖ SHA-256(room config) ‖ D)`, where D is the 64 bytes of `ur-enclave-v1` at provisioning or `ur-enclave-session-v1` at each attach, computed in the room; the room config shows `sealed`, the dedicated hotel, `network` and `network_capability` | the provisioning key and the incarnation's SSH host, identity, client and reader keys, all made in the room |

Under Path B the device checks, in order:

1. The SNP report as in Path A, with `MEASUREMENT` in the policy's `cathedral` hotel profiles (`listed`, with the signed release's hash recorded) and `HOST_DATA` equal to the policy's value for that hotel.
2. The room config Cathedral returns: `sealed` true, `tenancy` dedicated, the pinned hotel, `network: internet`, `network_capability: tun`.
3. The report data recomputed from the sandbox id, which must equal the VM id the adapter reported for this incarnation, the image digest the policy pins for B's image version, the config's hash, and D.
4. D recomputed as `ur-enclave-v1` over the device's own nonce, SHA-256(B) and H.

Only then does it seal to P. At each attach, `ur ssh-server` asks the in-room endpoint for a report whose D is `ur-enclave-session-v1` over the device's nonce and the SSH exchange hash (§12.6). Without Ask 3 there is no attach binding either.

### 4.4 Key provisioning

§11.7's steps 7 to 9 stand. P is made in the room or guest; the device seals the auth key, genesis anchor and settings to P; the broker carries the sealed bundle to the room's init, which polls for it with its VM token, so nothing needs to reach the room inbound. Cathedral's own sealed secrets and encrypted exec, which encrypt to the hotel's keys, aren't used: the hotel would open them, and its key source is "install".

### 4.5 Egress

Rooms are created with `network: internet` and `network_capability: tun`. `ur tun` owns the room's routes, and the init installs §11.8's fail-closed rules in the room's own network namespace. The default stays `auto`, through URnetwork. `direct` leaves from the host's single address, which every enclave on it shares, through the hotel's egress policy ("The hotel's egress policy still applies"). Outbound 25 is refused by our rules. IPv6 reaches the internet only over the overlay to exits. UDP is proven at the gate.

### 4.6 Payment through the compute balance

- **The person pays URnetwork.** `enclave_run` per second at the shape's price times 1.20 (§9.6), held 10 minutes ahead (§9.7): `cpu-2` on `sealed-4x8` is $0.024 an hour, about $17.50 a month; `cpu-4` on `sealed-8x16` is $0.048, about $35. Cathedral's price list shows no egress charge, so there's no `enclave_host_egress` charge unless the agreement adds one.
- **URnetwork pays Cathedral.** SN94 gamma, minted just in time and spent at Cathedral's service hotkey (§10.4), once Ask 7 makes gamma pay for the dedicated host. SN94's pool is thin (about 2,279 TAO on 23 November: 0.23% price impact for a $1,000 mint, 2.24% for $10,000), so §10.4's 1% ceiling holds each mint under about $4,000, more than two days' spend at any likely volume.
- **Reconciliation.** Per room, from `GET /v1/sandboxes/{id}/usage` against the `enclave_run` charges (§10.7).
- **A reservation is a different model.** If [the dedicated host] is billed as reserved capacity, URnetwork carries a fixed monthly cost that per-second charges recover only near full: at Cathedral's reserved price, 640 GiB costs what 67 of the 80 possible 8 GiB enclaves bring in at 1.20 (Q-CATH-6).

### 4.7 Restarts, failure and deletion

- **A re-seal ends every room at once.** "The room is not a separate VM and ends if the host restarts" (p.4), and Path A's VMs would likewise end with the host. Every incarnation on the host fails together, on Cathedral's report, never on silence (§11.11). Keepers restart them on the same chip, which §11.7 allows without a person. Each stop rotates every repo its sponsor reads (§11.17's high-likelihood risk), so one re-seal sets off a burst of rotations across every sponsor on the host.
- **No make-before-break on one host.** With a single host, a planned restart of the indexer can't start its successor first (§11.10): mail waits on senders' retries for as long as the re-seal takes. A second host, or Hippius beside it, restores make-before-break.
- **Silence and spend caps.** Silence alone still fails nothing. A room that hits its spend cap ends; the adapter keeps the cap ahead of the room's running time.
- **Deletion.** §11.11's remove runs as written: the incarnation signs its own `SidecarRevoke`, then `DeleteVm`. "Deletion removes its files; save anything you need first" (cathedral.computer/docs/); the room's keys die with its memory. Cathedral keeps its create receipt (image digest), usage and times. Under a sealed room there are no command receipts.

### 4.8 What the disclosure must say

§2.8's shared form, filled for Cathedral, version 1, proposed. Under Path B:

```text
enclave:cathedral · version 1 · AP: in a TEE, Cathedral trusted · asks before creating one there
Summary: A TEE on a machine Cathedral runs for URnetwork in <city>. Your own enclave is one of your devices
and holds what they hold, so Cathedral, a physical attack or a breach there could expose all of it.
```

The template's lines stand, with `<inside>`, the machine's holder and these lines filled:

- `<inside>`: "Cathedral's machine software, which only Cathedral can rebuild today, the key with which Cathedral approves that software, and the container software that keeps each enclave on the machine apart from the others."
- The holder line names who holds the machine, which Ask 6 must answer, in place of "a miner you do not know".
- If enclaves of several networks share a guest (Q-CATH-3): "Other URnetwork members' enclaves run on the same machine and share its software. A flaw there could let one reach another."
- "When Cathedral restarts the machine, for an update or a fault, every enclave on it stops at once and starts again with new keys. If this is your network's mail indexer, mail waits on senders' retries meanwhile."
- "Under direct egress, which you approve, its traffic leaves from the machine's own address, which every enclave on it shares."
- "Cathedral sees URnetwork's account and each enclave's size, image, times and usage, never your name, your network's or your enclave's."
- In Private, the disk line reads "encrypted in memory, and on disk under a key made each time the machine starts".

Under Path A, if the gate earns A1, the summary reads "A TEE of your own on a machine Cathedral runs for URnetwork in <city>. Your device checks everything that runs in it.", and the provider line reads "Nothing of Cathedral's runs inside your enclave: it boots URnetwork's image, which your device checked. Cathedral runs the machine around it." Today's line, "Cathedral's sandbox platform, as its gate documents it" (§2.8), understates Path B and overstates nothing under Path A, so it must change either way.

### 4.9 Design text to fold

DESIGN-COMPUTE.md is assembled from sources, so these go in through the design-records track, not by hand.

**Owner statements**, a new row:

| # | The owner's words | Binds |
|---|---|---|
| CO-50 | "Cathedral came back and gave us this integration guide: ~/urnetwork/factury/sidecar/URnetwork_Implementation_Guide.pdf . Incorporate this and see if we can include Cathedral in version 1 as another enclave optioon. I'd like to have more than one option." (2026-11-27; DESIGN-UI's UI-21) | §2.8, §4.4, §4.7, §5.5, §11.3, §11.5, §15.1, §19 |

**§4.4's Cathedral row**, replacing L803:

| Provider (subnet) | Inference in a TEE | Enclave (TEE VM) | Evidence a client can fetch | E2E to the TEE | Gamma | Terms | Verdict |
|---|---|---|---|---|---|---|---|
| **Cathedral** (SN94; Polaris Cloud LLC, `api.polaris.computer`) | not for URnetwork | a dedicated AMD Turin SEV-SNP host whose rooms are containers in one guest VM: image by digest, root, `CAP_NET_ADMIN` and tun, until deleted; no SSH; exec through the API; a guest of our own "Pending" (guide p.1) or "Not available" (p.6) | hotel and sandbox reports carrying the caller's 64 bytes, through the API only; no report a room can ask for; measurements signed under an interim key, not reproducible outside Cathedral | its own, to the hotel's keys, not per enclave | yes on btauth/1 routes; the dedicated host's account takes USD credit | public terms without DPA or resale clauses; a 99.5% SLA on the dedicated host (guide) | **chosen (CO-28), gated**: fails EPC-1 and EPC-2 as offered on 2026-11-27; A1 possible with a guest per enclave booting `ur-enclave`, AP with sealed rooms that attest themselves |

**§11.3's status row**, replacing L2910:

| Provider | EPC-1 | EPC-2 | EPC-3 | EPC-4 | EPC-5 | EPC-6 | EPC-7 | EPC-8 | Gap to close |
|---|---|---|---|---|---|---|---|---|---|
| Cathedral (SN94), SEV-SNP, dedicated host | no: rooms run unmeasured images by digest; no guest of our own; `HOST_DATA` per host at a re-seal, not yet bound; no SSH; exec reaches running rooms | no: reports only through the API, carrying the caller's 64 bytes | yes, as claimed: root, `CAP_NET_ADMIN` and tun in a container | IPv4, UDP to prove; no IPv6 | API: create, status, lifetime, usage, delete | partly: URnetwork alone, but every room shares one guest | partly: btauth/1 routes take gamma; the dedicated host's account takes USD | none published | a guest per enclave booting `ur-enclave` with `HOST_DATA` = SHA-256(B), or sealed rooms that refuse every command and an in-room report binding the room's id, image and config with 64 bytes it chooses; gamma for the dedicated host; E6; EPC-9's cadence |

**G-PROV-cathedral**, replacing §4.7's L873 (and §19.2's L4277 to match):

> enclaves on Cathedral | a signed agreement in place of general availability, covering E6, the dedicated host's SLA and notice before any re-seal; EPC-1 to EPC-9 (§11.3), by a guest per enclave booting `ur-enclave` with `HOST_DATA` = SHA-256(B), or by sealed rooms that refuse every command, file, process, console, snapshot and fork from every caller, Cathedral's own included, and attest themselves under `cathedral-room-v1` (§5.5); the room runtime, its capabilities and the image's measurements documented; the dedicated host's chip pinned in the policy, with no other hotel on it; §18's enclave and attestation tests run on the dedicated host; SN94's gamma credits a test hotkey and pays for the dedicated host; under sealed rooms, one network per guest for agents' enclaves (Q-CATH-3); the external audit of §11.7 and §12 done

**§2.8's provider line** for Cathedral: 4.8's text for whichever path passes.

**§5.5**: 4.3's `cathedral-room-v1` row, under Path B only.

**§11.5**: a note under the shapes table: "Cathedral's templates give 4 GiB of memory per 2 vCPU, so `cpu-2` runs on `sealed-4x8` and `cpu-4` on `sealed-8x16`; Cathedral offers no `cpu-8`; scratch is Cathedral's disk budget, shown on the create sheet, until it reaches the table's."

**§15.1**: `ur enclave create <name> --shape <s> [--provider <p>] [--egress …]`, where `--provider` names a provider whose gate passed, else the person's default, else the network's first allowed, and the approval names it; and a new `ur enclave providers`, listing each enclave provider as open or gated (naming its gate), its label, CPU, place, shapes, prices and the disclosure version the person acknowledged.

**§11.14**, three rows:

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Cathedral's rooms as offered on 2026-11-27 | a second CPU provider now; root and tun; an SLA | rooms share one guest; no report a room can ask for; exec reaches running rooms from URnetwork's account and from Cathedral's API and broker | rejected: EPC-1, EPC-2, the directive |
| URnetwork's own room runtime as the dedicated host's `HOST_DATA` bootstrap | takes Cathedral's runtime and exec out of the guest, using a feature Cathedral has built | a runtime for many networks to build and audit; each change a re-seal that ends every enclave; the guest still shared | Later, only if Cathedral offers neither a guest per enclave nor sealed rooms |
| Cathedral as a keyless code sandbox for agents | something of Cathedral's in version 1 | not an enclave, and whoever holds URnetwork's account key reads what agents put there: a server reading content (§0) | rejected |

**Q-ENC-1's answer**: "…Cathedral, for CPU, once it gives each enclave its own guest booting `ur-enclave`, or seals its rooms and lets them attest themselves, and signs E6 (G-PROV-cathedral)…"

## 5. What a person sees with two providers

- **Create a remote harness** (DESIGN-UI's T3, the bot tab). The sheet lists both providers under Provider, as the mockup already draws them (design/mocks/ui-app.html, T3). Each row gives the name, the CPU ("AMD SEV-SNP"), what the person gets ("A VM of your own" for Hippius and for Cathedral under Path A; "A room on a machine shared with other URnetwork enclaves" under Path B, if Q-CATH-3 allows it), where it runs, the label line ("Hippius trusted" or "Cathedral trusted" at AP; "Checked end to end" at A1), the shape's price, and the disclosure line, which opens the full text. A provider whose gate hasn't passed shows "Opens after its checks pass" and can't be picked. The preselected one is the person's last choice, else the network's first allowed open provider, ranked A1 first, then Hippius as the owner's recommended (Q-UI-9), then price; it is never switched silently. Choosing a provider the person hasn't acknowledged opens its disclosure first.
- **An enclave an agent creates.** `enclave_create` takes an optional provider, defaulting to the person's choice above. Kind 19's card names the provider and its disclosure line, and the device's step 6 accepts evidence from that provider alone (§11.7). Without an acknowledgment, a run with no person attached gets `disclosure_required`.
- **The indexer enclave** (B10, B11). An Owner or Admin sees the same list, limited to providers whose placement passes the Where row. Cathedral's row adds "Restarts when Cathedral updates the machine; mail waits on senders' retries meanwhile." Each member's mailbox grant names the provider and opens its disclosure, and a move to the other provider asks every member again (§11.10).
- **Cards** (T2, B11, the agent details). "cpu-4 · Cathedral · AP", with the place, in the same position as "cpu-4 · Hippius" today. Moving an enclave from one provider to the other is a stop and a start, a new kind 19.
- **Network policy.** Team admins choose which enclave providers the network allows and may require A1 (§16.4), shown in the Team screens' compute settings.
- **The CLI.** `ur enclave providers`, and `--provider` on `ur enclave create` (4.9).
- **Labels.** Each provider keeps one label everywhere: "AP · Hippius trusted"; "AP · Cathedral trusted" under Path B, or "A1" under Path A; "Opens after its checks pass" while gated. No surface says just "TEE".

## 6. Version 1: Cathedral can't be ready for the mid-December merge

The owner put encrypted enclaves in the first release (mmm/outbound/PLAN.md Q-OB-10, 2026-11-26); DESIGN-COMPUTE still phases them at M14, behind a provider's gate and the external audit. The merge is about 18 days away.

### 6.1 The work and its size

| Work | Size | State today |
|---|---|---|
| M14's platform, which any provider needs: the SEV-SNP verifier (1 to 1.5 engineer-months), image, measurement pipeline, orchestrator, provisioning, egress and scratch (6 to 8), the SSH client and server (2 to 2.5), the enclave Harness and attach (2.5 to 3) and the rest of §19.4's M14 line | 18.25 to 25.25 engineer-months in all (§19.4) | the agents' and edit containers and their socket (ENC-M14-13, -14) and the provider registry; the rest isn't in the tree |
| Cathedral's adapter | 1 to 1.5 engineer-months for production (§19.4); 2 to 3 engineer-weeks as a draft against the guide (QD-1233) | Cathedral's slot only |
| Path A's extra: Cathedral's measurement profile for `ur-enclave` | about a week, once Cathedral publishes its firmware and VM layout and the image exists | waits on Ask 1 and the image |
| Path B's extras: a room build of `ur-enclave`, `cathedral-room-v1`, sealed-room tests | 3 to 5 engineer-weeks, once Cathedral documents Asks 2 and 3 | waits on Cathedral |
| The staging pilot and §18's tests on [the dedicated host] | 2 to 3 engineer-weeks | not started |
| The provider choice in the apps, the sdk's view controller and the CLI | 1 to 2 engineer-weeks | drawn in the mockups |
| The policy's Cathedral lines and the disclosure, with a second person reading each translation | days | not started |
| Outside the build: Cathedral's changes, a signed agreement, G-GAMMA-treasury, the external audit | weeks to months, set by others | none done |

§19.4's own reading: enclaves come "about 3 to 5 months after the commitment, the platform ready by then".

### 6.2 What must be true by the merge, set against the gate

| For Cathedral to be a user-facing option at the merge | Today | By mid-December? |
|---|---|---|
| Ask 1, or Asks 2 and 3, live on [the dedicated host] and documented | none offered; the in-room report is "not required to run on this host" (p.4) | no |
| A signed agreement covering E6, the SLA and re-seal notice | public terms only | no |
| Gamma paying for the dedicated host | USD credit only | unlikely |
| M14's platform built, and Cathedral's path tested on [the dedicated host] | mostly unbuilt | no |
| The external audit of enclave provisioning | not done | no |
| `enclave:cathedral` and Cathedral's profiles and chip pin in the production policy | none | no, since each waits on the rows above |

So the honest answer to "can we include Cathedral in version 1" is no, and the same holds for Hippius under the current design.

### 6.3 What version 1 can carry

1. The enclave screens with both providers listed and each marked "Opens after its checks pass"; `ur enclave create` answering `no_enclave_provider` and naming both gates (§11.3); copy that names no enclave as available, as the outbound plan already requires ("The email names no remote enclave until a provider passes the gate").
2. Cathedral's adapter as a draft against the guide's API and fakes, kept out of the catalog and the production policy (QD-1233).
3. The staging pilot's first results from 3.2, if the owner approves it (Q-CATH-11).
4. `enclave:cathedral`'s text in the staging policy only.
5. The asks in 3.3, sent by the owner, and this report's design text folded through the sources (Q-CATH-13).

### 6.4 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Cathedral can't or won't build a guest per enclave or sealed rooms | medium | no Cathedral enclaves | ask now; Hippius in parallel; no user data on [the dedicated host] meanwhile |
| The command channel: URnetwork's key, or Cathedral's API and broker, run commands in an enclave | certain today | every enclave on the host read whole, and its sponsor's whole vault with it (CO-43) | Ask 1 or Ask 2; nothing of a user's on Cathedral until then |
| One host: a physical attack on it exposes every enclave there, and TEE.fail's interposer reaches Turin with DDR5 (§2.6) | low per machine | everything on the host at once | the disclosure says so; a second host spreads it; chip pinned, so the broker can't aim elsewhere |
| A shared guest: one member's root, or an agent's escape, reaches others' enclaves | medium (§11.17 rates container escape medium) | other networks' enclaves | Path A; one network per guest; `runsc` if Path B is forced |
| Re-seals: every enclave restarts together, with unknown frequency and notice; the host was re-sealed on 27 November | high | outages; a burst of repo rotations; indexer mail delays | notice in the agreement; two weeks of measurements before the gate |
| Vendor maturity: preview; measurement key on an operations server; builds not reproducible; a small subnet (under 0.01% of emission, $2.5 million market cap on 23 November) | medium | a bad image approved; the provider leaving | profiles reviewed before entering the policy (§5.4); G-PROV-any; small balances (§10.4) |
| A reservation billed monthly before any user can use the host | medium | about $1,168 a month at Cathedral's published reserved price | Q-CATH-6 |
| Terms: no DPA, suspension without stated notice, liability capped at three months' fees | high until signed | an account suspended with every enclave on it | E6 in writing |
| Shapes and disk: 10 GiB of disk, 4 GiB per 2 vCPU | certain | builds that don't fit | Ask 10; sizes shown on the sheet |
| UDP and the room's namespaces unproven | medium | connect falls back to TCP; IC-14 unbuildable in a room | the pilot's tests; Path A |
| The guide's key leaks: it was printed in a PDF | medium | anyone holding it can run commands in every room | rotate it; vault only |

## 7. Facts that contradict the design or the earlier research

1. **EPC-6 is not "yes".** §11.3's table marks Cathedral's EPC-6 "yes", and §2.3 says other customers of an enclave provider see "none (EPC-6)". Rooms share one guest: on Cathedral's shared pool, "Several customers' rooms share one machine" (cathedral.computer/docs/); on the dedicated host, every URnetwork enclave shares one guest (p.1, p.2).
2. **No setup over SSH is coming.** §11.3 expects Cathedral could qualify by setup over SSH once "SSH into a sandbox, not yet live" arrives. The guide says "There is no SSH, cloud-init or metadata service" (p.4) and lists no SSH among its open items (p.6); the docs say "There is no SSH into a confidential sandbox". §19.7's note that setup over SSH is built "only if the first provider to commit qualifies by it" won't be triggered by Cathedral.
3. **EPC-1, EPC-2 and EPC-3 are now known.** §11.3 marks them "unknown". EPC-1 and EPC-2 fail as offered; EPC-3 is met as claimed.
4. **More sits inside the boundary than §2.8 says.** "Cathedral's sandbox platform" leaves out Cathedral's API and broker, which can send requests into a room; the measurement-signing key on an operations server; and every other room on the hotel.
5. **Cathedral does have E2E, to the hotel.** §4.4 leaves Cathedral's E2E column empty, but Cathedral encrypts commands and secrets to the hotel's X25519 keys (`x25519-hkdf-sha256-aes256gcm-v1`), one set for the whole hotel, not per enclave.
6. **Cathedral's TDX machines are gone.** The earlier research recorded "one-shot runs on 'its own fresh Intel TDX machine'"; Cathedral's Intel TDX service is retired and `custom.v1` whole-machine orders are closed.
7. **A provider does offer an SLA.** The report says no provider offers one; the guide gives "99.5% monthly on the dedicated host" (p.2).
8. **Payment differs from what the design assumes.** §10.4 has the broker call gamma-native providers with btauth/1 under K_P. The guide uses a bearer account key, the account is funded with prepaid USD by card, USDC or TAO, gamma pays only btauth/1 routes, and reserved hotels are billed monthly. The home page, as fetched, lists no payment method, where the earlier notes found "Pay with Gamma, no account".
9. **Shapes don't fit.** §11.5 offers 8, 16 and 32 GiB with 64, 128 and 256 GiB of scratch; Cathedral offers 2, 4, 8 and 16 GiB, nothing above 8 vCPU, and 10 GiB of disk on [the dedicated host] (p.2).
10. **The scratch volume differs.** §11.9 makes each incarnation's scratch with dm-crypt and dm-integrity under a key the init makes. Cathedral's guest encrypts scratch "with a per-boot key", and "The current XTS data volume has no authenticated blocks or rollback counter"; whether a room can run device-mapper itself is untested.
11. **`HOST_DATA` isn't what §11.3 planned for.** It is one value per host, applied at a re-seal, not yet bound (p.3, p.6), and the live binding already carries a value whose meaning isn't documented.
12. **The holder may be a hosting company, not only a miner.** The design's texts assume "a miner you do not know". Cathedral's docs say the physical host is "often a miner", and [the dedicated host]'s egress is on [a bare-metal hosting company]' network, which points to a rented bare-metal server in a data center. Who rents it isn't stated (Ask 6).
13. **The team and endpoint.** §4.4 notes "SN49 Polaris (deregistered by 2025-11-01)". Cathedral's terms say it is "operated by Polaris Cloud LLC", its API is `api.polaris.computer`, and its support address is at polariscloud.ai. D-PROV-4 names a provider by team and endpoint, so the adapter's record should name Polaris Cloud LLC and `api.polaris.computer`.
14. **Plaintext paths moved, but remain.** The earlier notes found typed input passing Cathedral's API "as plain text in 'Send unencrypted' mode". Encryption is now the default in Cathedral's clients (ctcli 0.6.0, cathedral-mcp 0.2.0), but env values on create, background execs, tar transfers and port URLs still pass in plaintext.
15. **Still preview.** The research's "Live testing, not general availability" now reads "Sign-in is unavailable on this preview"; the guide calls the dedicated host "live".

## 8. Decisions for the owner

**Q-CATH-1. Is Cathedral a user-facing enclave option in version 1?** *Options:* (a) no: list it as "Opens after its checks pass", build its adapter as a draft, pilot [the dedicated host] in staging and send the asks; it opens when G-PROV-cathedral passes; (b) yes, on [the dedicated host] as it stands, labeled AP with a disclosure saying Cathedral and URnetwork's account can run commands inside; (c) yes, for something narrower, such as a code sandbox holding no keys. *Recommendation:* (a). (b) offers a server path that can read every enclave on the host, which §0 calls "a design error … never offered as an option", and it fails IC-3; (c) isn't an enclave, and the account key still reads whatever agents put there.

**Q-CATH-2. What do we ask Cathedral for first?** *Options:* (a) a guest per enclave booting `ur-enclave`, with `HOST_DATA` = SHA-256(B) (Ask 1); (b) sealed rooms and an in-room report (Asks 2, 3); (c) both: (a) as the target and (b) as the bridge, with Asks 4 to 13. *Recommendation:* (c), leading with (a). It meets EPC-1, -2, -3 and -6 at once, keeps §11.7 unchanged, and could make Cathedral the first A1 enclave provider; the guide's "Need Ur imagine to sample" (p.1) suggests Cathedral would look at it.

**Q-CATH-3. Under sealed rooms, may different networks' enclaves share one Cathedral guest?** *Options:* (a) no: one network per guest, which at Cathedral's reserved price (about $1,168 a month for a full hotel) suits a Team that buys its own host through Services (UI-18), not individual members; (b) yes, with gVisor (`runsc`) as the room runtime, disclosed; (c) yes, disclosed. *Recommendation:* (a). Each agents' enclave holds its sponsor's whole vault (CO-43), and each sponsor has root in their own enclave (§11.10, §12.5), so one member's escape from a container would read every other network's enclaves on the host. §11.14 rejected this layout for the same reason.

**Q-CATH-4. May a signed agreement for a dedicated host stand in for "general availability" in G-PROV-cathedral?** *Recommendation:* yes, if it covers E6, the 99.5% SLA and notice before any re-seal. It binds Cathedral more than a public GA label would.

**Q-CATH-5. How is Cathedral paid?** *Options:* (a) SN94 gamma only, through btauth/1 under K_P on the dedicated routes or credited to the account holding the host; (b) prepaid USD credit by card or USDC until (a) exists. *Recommendation:* (a). (b) is the payment CO-10 and CO-32 rule out ("Any provider that does not accept gamma at launch will be dropped from launch").

**Q-CATH-6. If [the dedicated host] is billed as a monthly reservation, do we keep it before any user can use it?** *Recommendation:* no. Ask Cathedral to bill the pilot per room-second, or to pause the reservation, until the gate passes. Decide any reservation at the gate against a forecast: at Cathedral's per-GiB price and the 1.20 markup, a full hotel breaks even only at about 67 of its 80 possible 8 GiB enclaves running all month, so a reservation pays only near full.

**Q-CATH-7. Which shapes does Cathedral offer?** *Options:* (a) map `cpu-2` to `sealed-4x8` and `cpu-4` to `sealed-8x16`, with no `cpu-8`, showing Cathedral's scratch size on the sheet; (b) add Cathedral-only shapes to the catalog; (c) list nothing until Cathedral matches §11.5. *Recommendation:* (a), with Ask 10's 64 GiB of disk a condition of the gate, since 10 GiB won't hold a toolchain and its caches.

**Q-CATH-8. What label and disclosure does Cathedral carry?** *Recommendation:* A1 under Path A if the gate shows nothing of Cathedral's runs in the guest and the profile is `reproduced`, else AP; AP under Path B, with 4.8's text; and no label at all while a command channel into enclaves exists, since then Cathedral is not offered.

**Q-CATH-9. Can the network's indexer enclave run on Cathedral?** *Options:* (a) only under Path A; (b) also in a sealed room on a guest holding no agents' enclaves; (c) anywhere Cathedral passes. *Recommendation:* (a), or (b) if the owner accepts AP for mail. Never beside agents' enclaves, whose sponsors have root. A dedicated host whose chip the signed policy pins satisfies the Where row, since the broker can't choose another machine. On one host, though, every re-seal pauses mail, so a second host, or Hippius, is needed for make-before-break.

**Q-CATH-10. What happens to the key in the guide?** *Recommendation:* the owner asks Cathedral to rotate it. The new key lives in vault for the `computeservice` staging hosts alone, never in a repo, a document or an agent's context. Since it can run commands in any room, no user's data goes to [the dedicated host] until Ask 1 or Ask 2 is live.

**Q-CATH-11. Do we pilot [the dedicated host] in staging now?** *Recommendation:* yes, under §11.3's pilot rule and D-CPHASE-4, with test data only: 3.2's tests and two weeks of restart measurements, at per-room rates (cents an hour) unless [the dedicated host] is already reserved.

**Q-CATH-12. What does version 1 promise about enclaves (Q-OB-10)?** *Options:* (a) version 1 ships the enclave screens with every provider marked "Opens after its checks pass", and its copy names no enclave as available; (b) the merge waits until a provider passes; (c) EPC-1 and EPC-2 are relaxed for version 1. *Recommendation:* (a). Neither Hippius nor Cathedral can pass by mid-December, and M14's platform and the external audit aren't done; (b) would hold everything else in version 1 for months, and (c) would break the directive.

**Q-CATH-13. Do we record UI-21 and fold this report's design text?** *Recommendation:* yes, through the design-records track: CO-50 for UI-21, and 4.9's rows for §2.8, §4.4, §4.7, §5.5 (Path B only), §11.3, §11.5, §11.14, §15.1, §19.2 and Q-ENC-1. DESIGN-UI's follow-on table gets one line: T3, B10 and B11 list Hippius and Cathedral, each gated, with the provider choice of section 5.

## Sources

- **The guide.** "URnetwork Implementation Guide", Cathedral, prepared 26 November 2026, open items as of 27 November, 6 pages; every page read, as rendered and as extracted text (pdftotext). It has no annotations, links, scripts or hidden text.
- **The design.** DESIGN-COMPUTE.md: owner statements CO-21, CO-28, CO-32, CO-33, CO-41 to CO-43; §2.2 to §2.8 (IC-3, the threats at L388-L392, the disclosures at L425-L459 and L554-L607); §4.3 to §4.7 (the Cathedral row at L803, the gates at L871-L873); §5.3 to §5.5; §9.6; §10.4, §10.5, §10.10; §11 whole (EPC-1 to EPC-9 at L2894-L2902, the status table at L2906-L2914, setup over SSH, Q-ENC-1 to Q-ENC-14); §12.6; §18's Setup over SSH and Enclaves rows; §19.1 to §19.7. DESIGN.md's owner directive. DESIGN-COMPUTE-AMENDMENTS.md's QD-1233. DESIGN-UI.md: UI-1 to UI-21, T2, T3, B10, B11, Q-UI-9; design/mocks/ui-app.html. mmm/outbound/PLAN.md section 7, Q-OB-10.
- **The earlier research.** design/reports/Bittensor TEE inference and enclaves.md; research_notes/Bittensor TEE inference and enclaves/ (other_subnets_survey.md, gamma_payments_treasury.md, all_inference_providers.md).
- **Cathedral's public pages,** fetched about 02:00-02:30 UTC on 28 November 2026: cathedral.computer (home, /terms); /docs/ (index), /docs/sandboxes/isolation/, /docs/sandboxes/host-surface/, /docs/sandboxes/signed-measurements/, /docs/sandboxes/what-cathedral-can-see/, /docs/sandboxes/egress-matrix/, /docs/sandboxes/limits/, /docs/sandboxes/persistent/, /docs/sandboxes/commands/, /docs/sandboxes/custom-images/, /docs/sandboxes/sealed-snapshots/, /docs/confidential/, /docs/pricing/, /docs/api/sealed-sandboxes/, /docs/api/account/, /docs/api/broker-guests/, /docs/api/sandboxes/; /approved-measurements.json, /approved-measurements.signed.json (release 36); /v1/gamma/services.json; /v1/hotels/[the dedicated host]/attestation.
- **The network.** RIPE whois for [its egress address] and AS204770.
- **The repo.** computeservice/provider.go, computeservice/reference_provider.go, the root's `enclave_*` and `attest_*` files, and the commit log, read for what's built.

## What the owner decided

- **Q-CATH-1, 27 Nov 2026: ship the screens, gated.** The owner: "Ship the screens, gated (Recommended)".
  - Version 1 ships the enclave screens with Hippius and Cathedral both listed as "Opens after its checks pass", and no copy says enclaves are available.
  - Cathedral is asked for one VM per enclave booting our image, and its host is piloted in staging with test data only.
  - The Bot email waits, or loses its enclave line, until a provider passes (PLAN.md Q-OB-35).
  - This narrows Q-OB-10: enclaves are in version 1 as gated screens, not as a service people can use.
- **Then, the same day, the owner overrode it.** The owner, answering Q-OB-35: "Enclaves are not gated. We have two providers at merge. Just reword to what we have."
  - Enclaves ship at the merge from two providers, and the gating above no longer applies. Q-OB-10 stands.
  - What this report found still has to be true for Cathedral before user data goes there: one network per guest, attestation that each enclave requests itself, and no command channel into a running enclave. Q-CATH-2 asks which path.
- **Q-CATH-2, 27 Nov 2026: as offered today.** The owner: "As offered today".
  - Cathedral enclaves ship at the merge as Cathedral's guide offers them: containers inside one shared SEV-SNP VM on URnetwork's dedicated host, with no attestation per enclave.
  - The API holding URnetwork's account key, and Cathedral's broker, can run commands inside a running enclave.
  - The owner directive's "no URnetwork-run component sees plaintext" therefore does not hold for Cathedral enclaves. This is the owner's exception, and every place a person chooses or uses a Cathedral enclave has to disclose it: the create sheet, the enclave's label, the Bot page, the trust page and the disclosure texts (DESIGN-COMPUTE §11, §2.6).
  - The design changes go through the compute design's records, not by hand: the provider table, G-PROV-cathedral, and the label (A1, AP or none; Q-CATH-8).
  - Rotating the account key printed on page 1 of the guide is still needed (Q-CATH-10).
- **Q-CATH-9, 27 Nov 2026: allow the mail indexer on Cathedral, with the disclosure.** The owner: "Allow it, with the disclosure". Members may put Burner's mail indexer on Cathedral. The create sheet says plainly that URnetwork's account key and Cathedral can read the mail it indexes, password-reset mail included. *(Recommended was: not on Cathedral as offered.)*
- **Q-CATH-5, 27 Nov 2026: the USD key at launch, gamma later.** The owner: "USD key at launch, gamma later (Recommended)". URnetwork pays Cathedral's dedicated host through the account key for the merge, and agrees a written date with Cathedral for the move to gamma. The key lives in the vault, rotated (Q-CATH-10). CO-32 gets a dated exception for Cathedral.
- **Q-CATH-6, 27 Nov 2026: pay per use first.** The owner: "Pay per use first (Recommended)". Enclaves start on per-second or per-minute billing on the dedicated host, if Cathedral offers it there, and move to a monthly reservation (about $1,168 a month for a full host) only once use shows it would cost less.
- **Q-CATH-4, 27 Nov 2026: Cathedral's public terms for now.** The owner: "Public terms for now". Enclaves launch on Cathedral's public terms (Polaris Cloud LLC), and a signed agreement is negotiated after the merge. That agreement would cover a data processing addendum, the right to resell enclaves to our users, notice before suspension, and the 99.5% SLA Cathedral offered. *(Recommended was: a signed agreement first.)* The trust page's sub-processor entry for Cathedral says which terms apply.
- **Q-CATH-3, 7, 8, 10, 11, 12 and 13, 27 Nov 2026: all accepted as proposed.** The owner: "Accept them all (Recommended)".
  - **Q-CATH-3:** networks share one VM, as offered.
  - **Q-CATH-7:** Cathedral's cpu-2 and cpu-4 sizes, and a request for 64 GiB of disk (10 GiB today).
  - **Q-CATH-8:** no TEE assurance label while commands can run inside an enclave. The badge reads "Cathedral: URnetwork and Cathedral can run commands inside".
  - **Q-CATH-10:** the account key printed in the PDF is rotated now, and the new key is kept only in the vault.
  - **Q-CATH-11:** the host is piloted in staging with test data before the merge.
  - **Q-CATH-12:** settled by Q-OB-35; enclaves are available at the merge.
  - **Q-CATH-13:** these decisions go into the compute design's records as CO-50 onward, not by hand-editing DESIGN-COMPUTE.md.
