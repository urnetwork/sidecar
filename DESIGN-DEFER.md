# Deferred decisions

Every decision the sidecar design defers, one entry each (owner decision 587): a feature, mechanism, row or task that the owner or the design moves to Later, past launch or to a later version. [DESIGN.md](DESIGN.md) says what is built; this document says what is not built yet, why, what stands in its place, and what bringing it back would take.

This file is generated, as DESIGN.md is. Its entries are in `design/source/defer/`, one file per DESIGN.md section, and `design/source/build.sh` assembles and checks them; `design/source/README.md` says how. Never edit this file by hand.

## How to read an entry

The stages are §23.4's. **v0** is what personal networks get at launch: milestones M0-M5 and M7-M9, with app hosts at M8. **v1** is M6, M10 and M7-M9's Team items; it is built in the same run as v0, on the same branches, and ships behind its milestones' gates. **Later** is everything outside M0-M10: it has no milestone, and unless its entry says otherwise it has no task and no code.

Each entry gives seven things:

- **Deferred.** What is deferred, with its ids: owner decisions, D-, Q- and R- items, the build's ledger ids (QD-), tasks and FS rows.
- **Why.** The reason the owner or the design gave. Where DESIGN.md gives none, the entry says so.
- **Launch instead.** What launch does in its place.
- **Lost.** What a user or an operator goes without until it returns.
- **Dark in code.** What is already built and switched off, and where, or the seam and the check that keep the place for it.
- **Held.** Tasks and tracks that wait on it.
- **To bring back.** What it would take: the design still to write, the decision to make, the trigger to watch, the switch to turn.

Under each entry's title are its stage and the subsections of DESIGN.md that point at it. A section points at an entry with one line where it describes the deferred thing.

## What is not here

- What the design rules out. §1.7's non-goals and each section's rejected alternatives are decisions, not deferrals.
- App, console and extension screens. Owner rule 6 puts the apps' UI out of scope, and the design gives the seams it uses.
- Work the build's review phase finishes before launch. That work is inside M0-M10. The exception is a check or a fold that an owner decision itself puts off to the review phase: it has an entry, with that stage, until the review phase lands it.
- A reversal. A mechanism the owner removes has no entry; the owner decision that removes it says what went.

## Adding an entry

A design-records pass that folds a deferral adds its entry here in the same change: the entry in `design/source/defer/`, under the section that owns the deferred thing, and a pointer in each DESIGN.md section the deferral touches. The build fails on an entry that lacks a field, on an entry no section points at, on a pointer to an entry that does not exist, and on an entry that cites an R-, D- or Q- item or a subsection DESIGN.md does not hold. When a deferred thing is built, its entry is deleted with its pointers, and the owner decision that brings it back says so.

## Index

99 entries, grouped by the DESIGN.md section that owns the deferred thing. "Described in" lists the subsections of DESIGN.md that point at the entry.

| Section | Entry | Stage | Described in |
|---|---|---|---|
| [§2 Trust model and threat model](#s2) | [Key transparency](#trust-key-transparency) | Later | §2.19, §10.16 |
|  | [A release log](#trust-release-log) | Later | §2.19 |
|  | [Web code transparency](#trust-web-code-transparency) | Later | §2.19 |
|  | [An external security review and audit](#trust-external-audit) | Later, unless the owner reinstates it | §2.19, §10.12 |
| [§4 Repositories, code placement, branches, and build](#s4) | [C4, the browser WebSocket carrier](#repo-c4-browser-carrier) | Later | §4.6, §4.18, §5.17, §18.17, §23.4 |
|  | [C17, a js connect build without gVisor](#repo-c17-js-connect-build) | Later, decided after §18's spike | §4.6, §4.18, §18.17 |
|  | [C7, caller lane keys and logical lanes](#repo-c7-logical-lanes) | Later | §4.6, §6.18 |
|  | [apt and yum repositories](#repo-apt-yum-repositories) | Open, decided at v1's exit review | §4.18 |
|  | [§4's v1 set](#repo-v1) | v1 (M6, M7, M10) | §4.18 |
| [§5 The Sidecar core: identity, keys, lifecycle, local state](#s5) | [Proof of possession on transport auth](#core-transport-proof-of-possession) | Later | §5.17 |
|  | [§5's v1 set](#core-v1) | v1 (M6, M10) | §5.17 |
| [§6 The sidecar subprotocol: envelope, RPC, streams, server push](#s6) | [Stream resume](#proto-stream-resume) | Later | §6.18 |
|  | [Hybrid-only TLS groups](#proto-hybrid-only-tls-groups) | Later | §6.18 |
|  | [Same-network P2P, turned on](#proto-peer-p2p) | Built at M6, off until an owner call | §6.18, §17.18 |
|  | [§6's v1 set](#proto-v1) | v1 (M6, M10) | §6.18 |
| [§7 Networks, teams, members, enrollment, and SSO](#s7) | [Stage 3 of the admin-credential fix](#team-stage-3-hard-gate) | Later, on app adoption | §7.19, §23.4 |
|  | [§7's v1 set](#team-v1) | v1 (M6, M10) | §7.19 |
| [§8 Access control: policy, compilation, distribution, enforcement](#s8) | [Client-checked prefix write rules](#acl-prefix-write-rules) | Later | §8.8, §8.12, §8.14, §8.19, §11.11, §11.17, §11.18, §11.22, §23.4 |
|  | [Client-attested postures](#acl-client-attested-postures) | Later | §8.19 |
|  | [§8's v1 set](#acl-v1) | v1 (M6, M10) | §8.19 |
| [§9 Abstract socket listeners and the scheduler](#s9) | [Region-aware listener selection](#sock-region-aware-selection) | Later | §9.17 |
|  | [Slow start for new listeners](#sock-slow-start) | Later | §9.17 |
|  | [Edge-delegated ticket keys](#sock-edge-delegated-ticket-keys) | Later | §9.11, §9.17 |
|  | [Registration over push](#sock-registration-over-push) | Later | §9.17 |
|  | [§9's v1 set](#sock-v1) | v1 (M6) | §9.17 |
| [§10 Group keys for evs: MLS and the GKM service](#s10) | [MLS](#keys-mls) | Later | §10.4, §10.9, §10.12, §10.16, §23.4, §23.8 |
|  | [Suite 0x0020 with hybrid authority signatures](#keys-suite-0x0020-hybrid-signatures) | Later | §10.16 |
|  | [SafeExportSecret](#keys-safe-export-secret) | Later | §10.16 |
|  | [Gen packs](#keys-gen-packs) | Later, at §19.9's gen trigger | §10.16, §19.18, §23.4 |
|  | [§10's v1 set](#keys-v1) | v1 (M6, M10) | §10.16 |
| [§11 Encrypted versioned storage: format, git service, head API, subscriptions](#s11) | [Compaction](#evs-compaction) | Later | §11.22, §23.4 |
|  | [The reclaim of expired ciphertext](#evs-expired-ciphertext-reclaim) | Later | §11.22, §23.4 |
|  | [Working-tree sync](#evs-working-tree-sync) | Later | §11.22, §23.4 |
|  | [Derived shares](#evs-derived-shares) | Later | §11.22, §23.4 |
|  | [Git's SHA-256 object format](#evs-sha256-object-format) | Later | §11.11, §11.22 |
|  | [Full sync on mobile](#evs-mobile-full-sync) | Later | §11.22 |
|  | [A state commitment over the token tree](#evs-state-commitment) | Later, if measurements ask for it | §11.22 |
|  | [Directory-resident children](#evs-directory-resident-children) | Later, if §22.8 shows the need | §11.22 |
|  | [A tool that moves placed repos between clusters](#evs-repo-move-tool) | Later, before the first cohort exhaustion | §10.16, §11.22, §19.18, §23.4 |
|  | [A per-cluster batcher](#evs-per-cluster-batcher) | Later, if §22.8 shows it saves a set | §11.22 |
|  | [A reverse citation index in pidx/](#evs-reverse-citation-index) | Later, if §22.8 shows scans binding | §11.22 |
|  | [A word complement or semantic layer in the search index](#evs-index-semantic-layer) | Later | §11.22 |
|  | [Elias-Fano key sets](#evs-index-elias-fano-key-sets) | Later | §11.22 |
|  | [Per-field postings](#evs-index-per-field-postings) | Later, if §22.8 shows field-scoped queries common | §11.22 |
|  | [A pass that collects orphaned slot objects](#evs-slot-orphan-pass) | Later | §11.22 |
|  | [§11's v1 set](#evs-v1) | v1 (M6, M10) | §11.22 |
| [§12 DNS: the ur.network zone and per-network zones](#s12) | [The Public Suffix List listing and the mail cut-over](#dns-psl-listing) | Later, once eligible | §12.16, §13.17, §14.16, §15.17, §23.4 |
|  | [Bring-your-own nameservers](#dns-bring-your-own-ns) | Later | §12.16 |
|  | [HTTPS and SVCB records](#dns-https-svcb-records) | Later | §12.16 |
|  | [`_mta-sts` waiting for every receiver's certificate](#dns-mta-sts-certificate-gate) | Review phase, once §13's issuance for receivers settles | §12.7, §15.5 |
|  | [§12's v1 set](#dns-v1) | v1 (M6, M7, M8) | §12.16 |
| [§13 The TLS edge and certificates](#s13) | [ECH in split mode](#tls-ech-split-mode) | Later | §2.19, §13.17 |
|  | [HTTP/3 on the edge's UDP 443](#tls-h3-edge) | Later | §13.17 |
|  | [Anycast for the edge](#tls-anycast) | Later | §13.17 |
|  | [§13's v1 set](#tls-v1) | v1 (M6) | §13.17 |
| [§14 The SMTP edge: outbound mail and abuse attribution](#s14) | [A designated-verifier prover](#smtp-designated-verifier-prover) | Later | §14.16, §23.4 |
|  | [DKIM2](#smtp-dkim2) | Later | §14.16 |
|  | [§14's v1 set](#smtp-v1) | v1 (Team, from M9) | §14.16 |
| [§15 The local email server, inbound mail, and burner email](#s15) | [Destination routing on a routed IPv6 block](#mail-destination-routing) | Later, if a routed IPv6 block is obtained | §15.17 |
|  | [Team burners](#mail-team-burners) | Later | §15.17 |
|  | [Edge reputation from receiver verdicts](#mail-edge-reputation) | Later | §15.17 |
|  | [Several named mail credentials per network](#mail-named-credentials) | Later | §15.10 |
|  | [§15's v1 set](#mail-v1) | v1 (M7, M8, M10) | §15.17 |
| [§16 The local MCP server, harness integration, and record primitives](#s16) | [A team's own legal holds](#mcp-team-legal-holds) | Later, with RS3's assurance stage | §16.18, §23.4 |
|  | [Regex queries](#mcp-regex-queries) | Later | §16.18 |
|  | [Semantic search and embedding](#mcp-semantic-search) | Later | §3.6, §16.18, §23.4 |
|  | [Transcript text in the vault's index](#mcp-transcript-text-index) | Later, once §22.8 measures it | §16.18 |
|  | [Delegating tasks to a worker's agent and sharing its run sessions](#mcp-worker-task-delegation) | Later | §16.18, §23.4 |
|  | [Directory requests sealed to their approvers](#mcp-sealed-requests) | Later | §16.18 |
|  | [A guest view of the directory for cross-network shares](#mcp-directory-guest-view) | Later | §16.18 |
|  | [A per-team setting for prose at member trust](#mcp-member-prose-setting) | Later | §16.12 |
|  | [The harness config's waiting keys](#mcp-harness-config-keys) | Later | §8.5, §16.7 |
|  | [SSH-signed approvals for high-risk actions](#mcp-sshsig-approvals) | Later, until a customer asks | §16.6, §16.18 |
|  | [The fresh-reader check on a directory admin's CLOSURE of a card or repo file](#mcp-card-closure-replay-check) | Review phase | §16.11 |
|  | [§16's v1 set](#mcp-v1) | v1 (M6, M10) | §16.18 |
| [§17 IP addresses, subnet routing, and port forwarding](#s17) | [L3 delivery](#bridge-l3-delivery) | Later | §17.18 |
|  | [Multi-hop maps](#bridge-multi-hop-maps) | Later | §17.18 |
|  | [IPv6 subnet routes](#bridge-ipv6-subnet-routes) | Later | §17.18, §23.4 |
|  | [§17's v1 set](#bridge-v1) | v1 (M6) | §17.18 |
| [§18 SDK, apps, and extension integration](#s18) | [The extension's own Worker](#sdk-extension-worker) | Later | §5.17, §18.17, §22.17, §23.4 |
|  | [Firefox session mode](#sdk-firefox-session-mode) | Later | §18.17 |
|  | [Browser Workers and ephemeral CLI hosts as remote-search requesters](#sdk-remote-search-requesters) | Later | §18.17 |
|  | [§18's v1 set](#sdk-v1) | v1 (M6, M10) | §18.17 |
| [§19 Server services: deployment, data stores, operations](#s19) | [Packing small segments on the HDD tier](#ops-small-object-packing) | Later, at its triggers | §19.18 |
|  | [The next metadata cluster](#ops-next-metadata-cluster) | Later, a tracked item at §19.9's triggers | §19.18, §22.17 |
|  | [The segment placement and added HDD capacity](#ops-segment-placement) | Later, a tracked item at §19.9's hdd trigger | §11.22, §19.18, §23.4 |
|  | [A second site or an off-site copy](#ops-second-site) | Later, decided from operating data | §19.18 |
|  | [§19's v1 set](#ops-v1) | v1 (M6, M10) | §19.18 |
| [§20 Tiers, quotas, metering, and billing](#s20) | [Auto-recharge of data packs](#quota-auto-recharge) | Later | §20.16 |
|  | [Invoicing above 25 seats](#quota-invoicing-above-25-seats) | Later | §20.16 |
|  | [Retuning taskworker's financial claim shares](#quota-financial-claim-shares) | Later, once service debits carry production volume | §20.16 |
|  | [§20's v1 set](#quota-v1) | v1 (M6, M10) | §20.16 |
| [§21 Abuse, safety, and legal process](#s21) | [Preservation holds, turned on](#abuse-preservation-holds) | Built at M5, off until counsel confirms | §21.18 |
|  | [§21's v1 set](#abuse-v1) | v1 (M6, M10) | §21.18 |
| [§22 Testing and verification](#s22) | [The synthetic main network](#test-synthetic-main-network) | Later | §22.17 |
|  | [§22's v1 set](#test-v1) | v1 (M6, M10) | §22.17 |
| [§23 Phasing, milestones, and rollout](#s23) | [RS3, recURd's assurance stage](#phase-rs3-assurance-stage) | Later | §20.16, §23.4 |
|  | [Compliance mappings](#phase-compliance-mappings) | Later, with RS3 | §23.4 |
|  | [Self-hosted and air-gapped installs](#phase-self-hosted-installs) | Later, with RS3 | §23.4 |

<a id="s2"></a>
## §2 Trust model and threat model

<a id="trust-key-transparency"></a>
### Key transparency

*Later. DESIGN.md: §2.19, §10.16.*

- **Deferred.** Key transparency, named in §2.19's and §10.16's Later rows and nowhere else in DESIGN.md. It has no requirement, D- item, task or FS row, and DESIGN.md does not say what such a log would hold or who would run it.
- **Why.** DESIGN.md gives no reason beyond the Later rows. Nothing in M0-M10 depends on it.
- **Launch instead.** Each network's authorization log is its own key record. Devices pin it, check every admission and key against it, and witness each other's heads through HeadCheck, alarming and stopping on a fork (§6.4, §7.9; owner decision 129).
- **Lost.** A check from outside a network's own devices that servers showed every device the same keys. A fork is caught only when two devices of the network compare heads.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design first: what is logged, who runs the log, who witnesses it, and what §2.8's list then publishes. Then an owner decision, tasks and FS rows.

<a id="trust-release-log"></a>
### A release log

*Later. DESIGN.md: §2.19.*

- **Deferred.** A release log, named in §2.19's Later row and nowhere else in DESIGN.md. It has no requirement, D- item, task or FS row.
- **Why.** DESIGN.md gives no reason beyond the Later row.
- **Launch instead.** A release is promoted: both holders of the offline two-person Ed25519 key sign its `SHA256SUMS`, and `install.sh` checks that signature before it installs (§4.10; owner decision 264).
- **Lost.** A public record of every promoted release. A signed release offered to one host and to no one else leaves no trace that others can find.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design for the log and for who checks it, then a step in the promotion that §4.10 describes.

<a id="trust-web-code-transparency"></a>
### Web code transparency

*Later. DESIGN.md: §2.19.*

- **Deferred.** Web code transparency, named in §2.19's Later row. It would let a visitor check that the page code a server gave them is the published code. It has no D- item, task or FS row.
- **Why.** DESIGN.md gives no reason beyond the Later row. Owner decision 76 (Q-TRUST-4) accepts served code now, labeled as such.
- **Launch instead.** Web pages decrypt with served code, and say so: ur.io/recurd and the team console are labeled as served code (§2.8's EX7), and their page Worker runs in its own key origin, read-only (§18.8).
- **Lost.** A visitor cannot tell altered page script from the published script. §18.8's disclosed row names who could alter it: the server, Cloudflare's page scripts, an XSS.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design for publishing and checking the web bundle's hash, and a decision on whether the label then changes.

<a id="trust-external-audit"></a>
### An external security review and audit

*Later, unless the owner reinstates it. DESIGN.md: §2.19, §10.12.*

- **Deferred.** An independent review or audit of the cryptography: the in-house MLS subset whose audit owner decision 43 planned, which is Later with MLS itself (owner decision 610), the key ladder, the storage format and path tokens, and the zero-knowledge mail proofs (owner decisions 99 and 119; Q-TEST-3, Q-TRUST-8, Q-KEYS-1).
- **Why.** The owner's words (owner decision 99): "No review at the moment, just get it working."
- **Launch instead.** The mlswg vectors and differential tests (owner decision 43), fuzzing (owner decision 101), and the outbound-mail gate as owner decision 99 restates it: sound by design analysis, working, fast enough and interop-tested. Product copy may say "end-to-end encrypted" with §2.18's unaudited-cryptography disclosure on the security page, no audit gating it (owner decision 119).
- **Lost.** Independent assurance. §2.18's risk row rates unaudited novel cryptography Medium likelihood and Critical impact, and the security page discloses it.
- **Dark in code.** Nothing: an audit is not code.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** The owner reinstates it, names a reviewer and a scope, and decides whether a release or the "end-to-end encrypted" copy then waits on the result.

<a id="s4"></a>
## §4 Repositories, code placement, branches, and build

<a id="repo-c4-browser-carrier"></a>
### C4, the browser WebSocket carrier

*Later. DESIGN.md: §4.6, §4.18, §5.17, §18.17, §23.4.*

- **Deferred.** C4 of §4.6's connect changes: a `GOOS=js` WebSocket H1 carrier with in-band auth and an Origin allowlist (owner decisions 22 and 26; §18.8). With it wait browser streams, socket dials from a browser (§18.4), HeadCheck replies from `read_only` page Workers (§7.9, §18.8; QD-227) and the extension's own Worker.
- **Why.** Owner decision 26 runs the browser HTTPS-only first, and connect streams follow C4. The page Worker needs no connect client for what it serves at RS1 and RS2.
- **Launch instead.** The page Worker runs on the `sidecar_http` leg, HTTPS-only, over §6's long-poll (§18.8, §18.10). Where a desktop `ur daemon` exists, the extension uses it through `ur native-host`.
- **Lost.** No stream or socket dial from a browser. A page Worker runs no HeadCheck, so a page's view is unwitnessed and shows no `witnessed_at` (§7.9's read_only row).
- **Dark in code.** Nothing is built. `make check`'s X9 rule holds C4 as `later` and fails when a js carrier over a browser WebSocket appears in connect (sidecar/check/x9_test.go).
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** C4 on connect's `sidecar` branch, templated on sdk/device_rpc_platform_js.go; the server admits `chrome-extension://` ids, the `moz-extension:` scheme and the key origin; the X9 row moves to a milestone. Then HeadCheck for read_only Workers and the extension's Worker follow.

<a id="repo-c17-js-connect-build"></a>
### C17, a js connect build without gVisor

*Later, decided after §18's spike. DESIGN.md: §4.6, §4.18, §18.17.*

- **Deferred.** C17 of §4.6: a `js` connect build without gVisor or the IP stack, for the extension's streaming Worker only (owner decision 22; Q-REPO-2's residual; Q-SDK-1; D-SDK-19).
- **Why.** A connect-only js/wasm main imports 42 gVisor packages, which puts `sidecar.wasm`'s size goal out of reach. The page Worker no longer needs C17, since it links no connect client, so only the extension's streaming Worker would, and that Worker waits on C4.
- **Launch instead.** The page Worker is built `-tags sidecar_http` and links no connect client, engine or IP stack (§18.10).
- **Lost.** Nothing beyond what C4's entry lists.
- **Dark in code.** Nothing is built. `make check`'s X9 rule fails when connect gains a gVisor-free js build that §4.6 has not decided (sidecar/check/x9_test.go).
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** §18.10's size spike gives the figures; the owner decides C17 on them; the change then lands in connect with C4.

<a id="repo-c7-logical-lanes"></a>
### C7, caller lane keys and logical lanes

*Later. DESIGN.md: §4.6, §6.18.*

- **Deferred.** C7 of §4.6, a caller lane key for non-IP sends (connect/transfer_logical_lane.go), and with it §6's explicit lanes per stream (owner decision 22; §6.12's alternatives; §6.18).
- **Why.** §4.6: `TransferKey` lanes suffice. §6's alternatives row adds that explicit lanes are off by default in connect and starve without floors.
- **Launch instead.** Streams share connect's `TransferKey` lanes. D-PROTO-4's review reopens the question if a stall is measured.
- **Lost.** One stream's backlog can delay another on the same lane.
- **Dark in code.** Nothing is built. `make check`'s X9 rule fails when a caller lane key appears on connect's send options (sidecar/check/x9_test.go).
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A measured cross-stream stall, then C7 in connect with floors for each lane, and §6's stream rules for choosing a lane.

<a id="repo-apt-yum-repositories"></a>
### apt and yum repositories

*Open, decided at v1's exit review. DESIGN.md: §4.18.*

- **Deferred.** apt and yum repositories for `ur` (owner decision 213; Q-REPO-6's option (b)).
- **Why.** Owner decision 213 ships no apt or yum repository. Q-REPO-6 asks how Linux users then update, and its recommendation is to let the owner decide at v1's exit review whether they need repositories.
- **Launch instead.** `.deb` and `.rpm` are direct downloads, and `install.sh` checks the offline key's signature. A Linux host updates when someone re-runs `install.sh` or fetches the next package. Homebrew and winget come with v1.
- **Lost.** `apt upgrade` and `dnf upgrade` never reach `ur`, so no update arrives on a Linux host without someone acting.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** The owner's answer to Q-REPO-6. Option (b) needs a second offline two-person GPG key, signing at promotion, and repository trees under ur.io/recurd.

<a id="repo-v1"></a>
### §4's v1 set

*v1 (M6, M7, M10). DESIGN.md: §4.18.*

- **Deferred.** §4.18's v1 row: connect change C18 at M6; C20 at M7 (owner decision 269); Homebrew and winget packages. C19's window accounting, once at M10, is withdrawn (owner decision 609).
- **Why.** Each belongs to a v1 milestone: cross-network shares and Team at M6, strict-mode mail at M7, storage format 2 and search at M10 (owner decisions 55, 163, 169).
- **Launch instead.** v0 uses the connect changes of M1-M5 (§4.6) and ships `ur` through `install.sh` and direct packages.
- **Lost.** Until those milestones: cross-network shares, `strict_chain`, and remote search's accounting.
- **Dark in code.** Built in the same run on the `sidecar` branches. C20 blocks M7's `strict_chain` (§4.18's Blocking row).
- **Held.** Nothing.
- **To bring back.** Nothing to bring back: each ships when its milestone's gate passes (§23.6).

<a id="s5"></a>
## §5 The Sidecar core: identity, keys, lifecycle, local state

<a id="core-transport-proof-of-possession"></a>
### Proof of possession on transport auth

*Later. DESIGN.md: §5.17.*

- **Deferred.** Q-CORE-4's option (c): a sidecar proving its ClientKey when it authenticates a connect transport (§5.17; §7.4's residual).
- **Why.** The peer review of 2026-11-04 closed Q-CORE-4 with (b) in v0 and left (c) for later, its residual stated in §7.4.
- **Launch instead.** A `strict_exp` bearer adds a DPoP proof by its ClientKey when it refreshes, exchanges a token or calls `POST /network/auth-client` (§7.4), so a copied token renews, exchanges and mints nothing.
- **Lost.** A token copied alone still authenticates a connect transport until its `exp` (§5's token row; §7.4's residual).
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design for the proof on connect's transport auth, which is a connect change §4.6 does not list, and its place in §6's Hello.

<a id="core-v1"></a>
### §5's v1 set

*v1 (M6, M10). DESIGN.md: §5.17.*

- **Deferred.** §5.17's v1 rows. At M6: several networks per daemon, with team networks (owner decisions 23, 55); the RFC 8628 device grant; agent subkeys; `.ur`'s `claims` and `project`; the directory's control methods, group, local state and settings; the `access_request` action and events (owner decisions 170, 171, 182). At M10: the index cache, search state and `Search` settings (owner decision 163); remote serving (owner decision 175); local deletion of dropped content (owner decision 173); the index, search and drop event kinds.
- **Why.** Team ships at M6 and storage format 2 with search at M10 (owner decisions 55, 163, 169).
- **Launch instead.** v0's daemon serves one personal network per daemon, with M1-M3's enrollment, config repo, gate and `.ur`.
- **Lost.** Until M6 and M10: team networks on a daemon, agent subkeys, the directory, and search.
- **Dark in code.** Built in the same run on the `sidecar` branches, behind each milestone's gates.
- **Held.** Nothing.
- **To bring back.** Nothing to bring back: each ships when its milestone's gate passes (§23.6).

<a id="s6"></a>
## §6 The sidecar subprotocol: envelope, RPC, streams, server push

<a id="proto-stream-resume"></a>
### Stream resume

*Later. DESIGN.md: §6.18.*

- **Deferred.** Resuming a broken stream where it stopped, named in §6.18's Later row. It has no D- item, task or FS row.
- **Why.** DESIGN.md gives no reason beyond the Later row.
- **Launch instead.** A stream that fails resets with TRANSFER_FAILED and its caller opens a new one. The stream's offsets leave room for a later resume (§6's errors rule).
- **Lost.** A long transfer that breaks starts again from its beginning at the stream layer.
- **Dark in code.** Nothing is built. The offsets in the stream frames are the seam.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design for which side keeps what, for how long, and how a resumed stream is authorized again, then additive wire fields.

<a id="proto-hybrid-only-tls-groups"></a>
### Hybrid-only TLS groups

*Later. DESIGN.md: §6.18.*

- **Deferred.** Offering and accepting only hybrid key-exchange groups in TLS, named in §6.18's Later row. It has no D- item, task or FS row.
- **Why.** DESIGN.md gives no reason beyond the Later row.
- **Launch instead.** TLS 1.2 and 1.3 with X25519MLKEM768 offered first (§13's versions row), so a peer that supports the hybrid group uses it and one that does not still connects.
- **Lost.** A connection to a peer without the hybrid group has no post-quantum key exchange.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A measurement of which peers lack the group, an owner decision on refusing them, and a settings field for the group list.

<a id="proto-peer-p2p"></a>
### Same-network P2P, turned on

*Built at M6, off until an owner call. DESIGN.md: §6.18, §17.18.*

- **Deferred.** Ending relay-only for same-network sidecar pairs (owner decision 296; D-PROTO-10; §6.6, §6.18, §17.18; QD-045, QD-583).
- **Why.** Owner decision 296 builds P2P at M6 and leaves it off until the owner calls it on its fault schedule and measurement.
- **Launch instead.** Every same-network pair stays relay-only.
- **Lost.** Every same-network byte is relayed, and debited, until that call.
- **Dark in code.** `SidecarProtocolSettings.EnablePeerP2p`, default false (sidecar/envelope_settings.go, sidecar/rpc_subprotocol.go).
- **Held.** Nothing.
- **To bring back.** §22's P2P fault schedule and measurement pass; §2.8's connect rows and §2.10 say that a pair on P2P learns each other's public addresses through ICE and that relays see no frames of that pair; the owner calls it; a network turns the setting on.

<a id="proto-v1"></a>
### §6's v1 set

*v1 (M6, M10). DESIGN.md: §6.18.*

- **Deferred.** §6.18's v1 rows. At M6: FriendsAndFamily shares with C18, and same-network P2P built behind its switch. At M10 (owner decision 169): the SEARCH pair, Hello's feature bits 0 and 1, and the control class's acceptance of SEARCH, the pair's contracts accounted like any peer's (owner decision 609, which withdrew C19's window accounting and the app hosts' keepalive).
- **Why.** Shares belong to M6 and remote search to M10 (owner decisions 86, 163, 169, 175).
- **Launch instead.** v0's wire is M1's and M2's, with M4's seals and control contracts and M5's streams; it freezes at M2, and M10's bytes are additive to it.
- **Lost.** Until M6 and M10: cross-network shares and remote search.
- **Dark in code.** Built in the same run on the `sidecar` branches. M10's bytes freeze at M10's Gn-out.
- **Held.** Nothing.
- **To bring back.** Nothing to bring back: each ships when its milestone's gate passes (§23.6).

<a id="s7"></a>
## §7 Networks, teams, members, enrollment, and SSO

<a id="team-stage-3-hard-gate"></a>
### Stage 3 of the admin-credential fix

*Later, on app adoption. DESIGN.md: §7.19, §23.4.*

- **Deferred.** §7.4's stage 3, the hard gate: all 27 AppAdmin routes refuse client credentials (owner decision 45; §7.19; §23.4).
- **Why.** Existing apps still send client credentials to those routes. Stage 3 waits until under 1% of active app clients do so for 14 days, or until `upgrade_required` enforces SDK `bc72b109`.
- **Launch instead.** Stage 1 before any sidecar ships: child and admin-refused clients are refused on the AppAdmin and OwnClientPayout routes, and an allowlist confines `strict_exp` bearers. Stage 2 before the first desktop sidecar runs beside an app or the extension.
- **Lost.** Until stage 3, an older app's own client credential still administers its network on those routes.
- **Dark in code.** The refusal is one predicate, `ClientRefusesAdmin` (server/model), which stages 1 and 2 already use.
- **Held.** Nothing.
- **To bring back.** The adoption measure passes, or `upgrade_required` is enforced; then the predicate refuses every client credential on the 27 routes.

<a id="team-v1"></a>
### §7's v1 set

*v1 (M6, M10). DESIGN.md: §7.19.*

- **Deferred.** §7.19's v1 rows. Team at M6: members, roles, invitations, switching, OIDC, domains, JIT, SCIM and `scim_signer`, OAuth clients, full `ur-cli` admin, the audit log, multi-admin teams, config wraps for member devices past the first 1,000 (owner decision 144), and the team directory (owner decisions 170, 171, 182). Every network at M10: `VersioningRules` and `IndexerSet`'s `search` service (owner decisions 157, 163, 164, 175, 178).
- **Why.** Team ships at M6 (owner decisions 55, 102) and storage format 2 at M10 (owner decision 169).
- **Launch instead.** Personal networks, n = 1: auth keys, enrollment, token exchange and the enforced config repo with its authorization log. The k-of-n verifier and proposals are built and tested at M2 though a personal network has one admin.
- **Lost.** Until M6: more than one member in a network. Until M10: versioning rules and search indexers.
- **Dark in code.** Built in the same run. M2's records reserve what M6 and M10 need: `ServiceSettings.directory` (D-TEAM-28) and the `VersioningRules` type.
- **Held.** Nothing.
- **To bring back.** Nothing to bring back: each ships when its milestone's gate passes (§23.6). The `admin_user_id` audit blocks members.

<a id="s8"></a>
## §8 Access control: policy, compilation, distribution, enforcement

<a id="acl-prefix-write-rules"></a>
### Client-checked prefix write rules

*Later. DESIGN.md: §8.8, §8.12, §8.14, §8.19, §11.11, §11.17, §11.18, §11.22, §23.4.*

- **Deferred.** `RepoPrefixRules`, the rules that hold a writer to path prefixes inside one general repo, which every reader checks and no server does (owner decision 586; QD-1032). It takes with it Q-EVS-3's v1 half, D-ACL-11's prefix clause, owner decisions 345, 415 and 416 with 559's filer rule, and D-EVS-18's clause for a ref-creating push; §8.8's statement and §8.12's `AllowPrefixWrite`, §11.8's gate clause and §11.11's prefix and new refs rows; DESIGN-DETAILS.md section 16 with its amendments to sections 5, 8 and 10; ledger ids QD-212, QD-791 to QD-795, QD-801 to QD-803, QD-826, QD-833, QD-1001 and QD-1042; tasks ACL-M6-04, EVS1-M6-04 to EVS1-M6-07 and TEST-M6-03.
- **Why.** The complexity review of 2026-11-17 counted the rules' cost: about 8.2k lines and rule hooks in 54 other files, 12 decisions, 158 KB of design, an 18-configuration TLA+ model, a clause in evs's gate and repair-push quotas. The rules are advisory at evs: a breaching push commits, and readers ignore it and repair it, and one breaching push stops a shared git-mode ref on every mount until an admin deletes and re-pushes it. The owner chose to defer them.
- **Launch instead.** A repo per prefix (D-ACL-11; Q-EVS-3's v0 answer). The repo is the write boundary: servers enforce it, and it limits reads as well. Agents keep their owned branches and overlays.
- **Lost.** Subtree write limits inside one repo or branch. A team that needs them splits the tree into repos and loses atomic commits across the split. What servers see does not change.
- **Dark in code.** One switch, `AclPrefixSettings.Enabled`, false in `DefaultAclPrefixSettings` (sidecar/acl_prefix_settings.go). Off: the log refuses a `RepoPrefixRules` at its position as a type this release does not carry, so the log goes on, and SignedType 0x1111 and `AclRepo.prefix_rules = 12` stay reserved (sidecar/acl_statement.go); no filer signs one, and `ur evs rules` refuses with `ErrAclPrefixRulesDeferred`, naming the deferral (sidecar/acl_prefix.go, sidecar/cli/cmd_evs_rules.go); no reader judges a push, journals, alarms, repairs or pin-pushes (sidecar/evs_prefix.go, sidecar/evs_prefix_repair.go, sidecar/acl_prefix_gate.go); evs's gate has no clause for a push that creates a shared ref (QD-803's, reverted). The rules' own tests and the `details/PrefixRules` model run with the switch on, and sidecar/acl_prefix_dark_test.go holds the launch default off.
- **Held.** TEST-M6-03, the rules' end-to-end schedule rows, breach helper and model in the gate; it left TEST-M6-02's and TEST-M10-06's needs. The core lane's track acl-prefix-group-atom-refused was dropped. QD-1042's reading waits with the rules: about 30 lines in sidecar/evs_prefix.go and a ruled-repo test, by which the prefix judge takes the walked removal behind an absent reply as its version.
- **To bring back.** An owner decision that reverses owner decision 586. Then: fold DESIGN-DETAILS.md section 16 and its amendments to sections 5, 8 and 10 into DESIGN.md; restore QD-803's gate clause in evsservice; build QD-1042's reading; release TEST-M6-03 and return it to TEST-M6-02's and TEST-M10-06's needs; turn the switch on only in a release that every device and api of a network runs, since the format limits and the log's verdict on the statement are every verifier's alike.

<a id="acl-client-attested-postures"></a>
### Client-attested postures

*Later. DESIGN.md: §8.19.*

- **Deferred.** Access rules that depend on a posture the client attests, named in §8.19's Later row after the Team mock (sidecar/design/mocks' team-management.html:847-850). It has no requirement, D- item, task or FS row.
- **Why.** DESIGN.md gives no reason beyond the Later row.
- **Launch instead.** Rules name subjects an admission fixes: sidecars, members, tags, groups and the autogroups (§8.5). No rule reads a device's state.
- **Lost.** A team cannot write a rule such as "only from a managed, patched device".
- **Dark in code.** Nothing is built. `sidecar/device`'s posture is a different thing, the forwarding role's checks between compiles (§17.8).
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design: what a client attests, who verifies it, how a rule names it, and what §2.8's list then publishes.

<a id="acl-v1"></a>
### §8's v1 set

*v1 (M6, M10). DESIGN.md: §8.19.*

- **Deferred.** §8.19's v1 rows. At M6: team networks (owner decision 55) with two-approver rules, scope hosts, the audit reader (owner decision 63) and config wraps past the first 1,000 member devices (owner decision 144); the team directory and its default rule (owner decisions 171, 180, 182); cross-network shares (Q-PROTO-3, Q-QUOTA-5, C18); peer-list filtering. At M10 (owner decision 169): `RepoVersioning` enforced with storage format 2 (owner decisions 163, 173, 183), and the `control` class's remote search (owner decisions 175, 178).
- **Why.** Team ships at M6 and format 2 at M10.
- **Launch instead.** v0 evaluates policy on personal networks from M2: `AclRows`, grant chains, access logs and every §8.8 statement are checked and folded from M2, the `directory` kind's default and `RepoVersioning`'s lock among them, so a device on M2 code computes what M6 code does (D-PHASE-9).
- **Lost.** Until M6: team policy and shares. Until M10: the versioning lock's enforcement and remote search's class.
- **Dark in code.** Built in the same run on the `sidecar` branches; M2 folds what M6 and M10 enforce.
- **Held.** Nothing.
- **To bring back.** Nothing to bring back: each ships when its milestone's gate passes (§23.6).

<a id="s9"></a>
## §9 Abstract socket listeners and the scheduler

<a id="sock-region-aware-selection"></a>
### Region-aware listener selection

*Later. DESIGN.md: §9.17.*

- **Deferred.** Choosing a listener by region, named in §9.17's Later row. It has no D- item, task or FS row.
- **Why.** §9.17: there is one lb site today, so there is no second region to prefer.
- **Launch instead.** §9.7's scheduler: P2C over the listeners of a name, with its per-dialer clamp on `est`.
- **Lost.** Nothing while there is one site.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A second lb site, then a region value on registrations and a rule in the scheduler.

<a id="sock-slow-start"></a>
### Slow start for new listeners

*Later. DESIGN.md: §9.17.*

- **Deferred.** Slow start in listener selection, named in §9.17's Later row. It has no D- item, task or FS row.
- **Why.** DESIGN.md gives no reason beyond the Later row.
- **Launch instead.** A new listener takes its share at once under §9.7's P2C and clamp.
- **Lost.** A listener that has just registered is not ramped up, so a cold one can take a full share of dials.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A measured overload of fresh listeners, then a ramp in the scheduler's settings.

<a id="sock-edge-delegated-ticket-keys"></a>
### Edge-delegated ticket keys

*Later. DESIGN.md: §9.11, §9.17.*

- **Deferred.** Ticket keys delegated to edge hosts, so that edges admit streams through a sockets outage (§9.11's alternatives row; §9.17).
- **Why.** §9.11's row gives its cost: keys on edge hosts, while C9 still needs Redis.
- **Launch instead.** The sockets service signs every ticket with keys it reads from vault, and listeners verify them (§9.6, §9.8).
- **Lost.** Edges do not survive a sockets outage: no new ticket is issued while sockets is down.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design for which keys an edge may hold and for how long, and a new §2.4 asset row for keys on edge hosts.

<a id="sock-registration-over-push"></a>
### Registration over push

*Later. DESIGN.md: §9.17.*

- **Deferred.** Listener registration carried over push, named in §9.17's Later row. It has no D- item, task or FS row.
- **Why.** DESIGN.md gives no reason beyond the Later row.
- **Launch instead.** A registration is a lease that the listener's own client renews by a heartbeat every 15 s, and it lapses 45 s after the last one (§9.5).
- **Lost.** A device that is not connected holds no lease, so its names answer nothing until it connects again.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design, since DESIGN.md says no more than the name: who holds a lease for a sleeping device, and how a wake reaches it through §18.7's push path.

<a id="sock-v1"></a>
### §9's v1 set

*v1 (M6). DESIGN.md: §9.17.*

- **Deferred.** §9.17's v1 row: affinity, with §13; Team scope hosts (owner decisions 40, 55, 58), the `smtp/` ones with §15.
- **Why.** Team ships at M6.
- **Launch instead.** v0's `sockets` service at M5: blinded names, `tls/` with §13, tickets, P2C, `SocketHint`, the Go API, `ur socket` and `ur share`.
- **Lost.** Until M6: affinity and Team's scope hosts.
- **Dark in code.** Built in the same run on the `sidecar` branches.
- **Held.** Nothing.
- **To bring back.** Nothing to bring back: it ships when M6's gate passes (§23.6).

<a id="s10"></a>
## §10 Group keys for evs: MLS and the GKM service

<a id="keys-mls"></a>
### MLS

*Later. DESIGN.md: §10.4, §10.9, §10.12, §10.16, §23.4, §23.8.*

- **Deferred.** MLS as v0's key distributor: §10.4's RFC 9420 subset on ciphersuite 0x0010, one group per repo with member devices as leaves, PrivateMessage commits, KeyPackages and Welcomes, external commits, epochs and their KEK_e, GenWrap and LeafWrap, sealed GroupInfo, acks, resync and the config and directory groups' leaves rule (owner decisions 1, 43, 44, 60, 113, 128, 144, 182, 361, 363 and 366; D-KEYS-1, -2, -3, -12, -14, -18 and -23; Q-KEYS-9; ledger ids QD-002, QD-074, QD-442, QD-464, QD-526, QD-616 to QD-618, QD-638, QD-641, QD-659, QD-747, QD-956 and QD-1040; DESIGN-DETAILS.md section 6's MLS rules, which wait with it: the roster rule with its committer and member clauses, its D-KEYS-27 row, KF2's and KF5's commits, the dropped-leaf and waiting-leaf hints, D-KEYS-24's Welcome pointer clause, §10.6's note on the claim key, and the commit legs of FS-15, FS-24, FS-97 and FS-104).
- **Why.** The complexity review of 2026-11-17 counted about 42.5k MLS-only lines, 15.9k of them production, about 23 decisions, 98 KB of DESIGN-DETAILS.md section 6, about 14 of KEYS' 36 tasks and 27-63 MB of heap at 1,000 leaves; and MLS kept an agent's repo keyless until a member device formed its group, and made recovery above 16 leaves wait for a leaf online. Wraps had grown into a full distributor already, serving agents, member devices past the first 1,000, Delegations and recovery codes. The owner chose wraps only (owner decision 610).
- **Launch instead.** Every group key RK_g goes by §10.5's `KeyDelivery` wraps: a join is a LATE delivery, a removal the REMOVE rotation, a resync fetches deliveries; gkm keeps no epochs, Welcomes, KeyPackages, GroupInfo or acks, so `gkm:<group_id>` is versioned by generation alone, and the format's epoch fields, GenRotate's `leaf_wrap` among them, stay unset.
- **Lost.** TreeKEM's post-compromise healing of the key-encryption keys: a copied keychain heals by §10.5's bounds, a reader at its ReaderKey's not_after plus the next generation, where a leaf healed in about 37 days (60 above 50 leaves). Each rotation costs about 1.37 KB a holder, about 1.37 MB and 1,000 objects at 1,000 holders, against one 72 B leaf wrap a leaf.
- **Dark in code.** The root's `mls_*` files, mlsinterop/, gkm's MLS files, gkmservice's epochs, groupinfo, keypackages, welcomes, acks and reform, and sidecartest's fake_mls, mlssuite and bench_groups stay on the branch, dark, for Later, with owner decision 99's deferred audit; the review phase reworks key formation (KF1 to KF7) onto deliveries and removes gkm's MLS routes and state or leaves them dark.
- **Held.** The MLS interop freeze (KEYS-M2-11's 0x0010), fuzzing of the `mls_*` decoders, and the MLS legs of FS-15, FS-20, FS-24, FS-97 and FS-104 leave the gates; QD-641's MLS engine rewrite is dropped; the core lane's gkm-guard-right-set is re-briefed to the routes wraps-only keeps. One fold of owner decision 610 waits for the review phase: §22.8's FS-15, FS-20, FS-24 and FS-104 rows, §22.10's table, §23.6's M2 row, §23.8's freezes and D-KEYS-10 still put the MLS legs and the 0x0010 interop at M2's exit, because the fault catalog is held to §22.8's text and KEYS reworks the four rows onto deliveries in the review phase; until then M2's gate runs the rows' drafted schedules, its sweep saying in an open item that their MLS legs count toward nothing (owner decision 627; ledger id QD-1086).
- **To bring back.** An owner decision that reverses owner decision 610. Then: freeze the MLS wire and suite 0x0010 on §22.10's interop artifact; return KF1-KF7's MLS steps, §7.9's leaves rule and DESIGN-DETAILS.md section 6's MLS rules; restore the interop, fuzzing and FS legs to their gates; and move existing groups onto MLS by a GroupForm under the ladder, which the generations carry unchanged.

<a id="keys-suite-0x0020-hybrid-signatures"></a>
### Suite 0x0020 with hybrid authority signatures

*Later. DESIGN.md: §10.16.*

- **Deferred.** Moving groups to ciphersuite 0x0020 by migration, with hybrid Ed25519 and ML-DSA-65 authority signatures (§10.16; owner decision 358's not-taken option (3)).
- **Why.** v0 freezes draft suite 0x0010. Owner decision 358 declined ML-DSA signatures on ReaderKeys from v0: they close one forgery route only, add ML-DSA keys to admissions and about 3.3 KB to each ReaderKey, and pull this Later work forward.
- **Launch instead.** Suite 0x0010, post-quantum against passive adversaries only, with Ed25519 authority signatures (§10.4, §10.5).
- **Lost.** A future forgery of an Ed25519 signature, by a forged admission or ReaderKey, would be retroactive. §2.18's risk row states it and the security page discloses it.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design for the migration: the new suite's objects beside the old, ML-DSA keys in admissions, and how a group moves without a gap in its ladder.

<a id="keys-safe-export-secret"></a>
### SafeExportSecret

*Later. DESIGN.md: §10.16.*

- **Deferred.** SafeExportSecret from draft-ietf-mls-extensions-11, named in §10.16's Later row. It has no D- item, task or FS row.
- **Why.** DESIGN.md gives no reason beyond the Later row. The extension is an IETF draft.
- **Launch instead.** The MLS exporter gives each epoch's key-encryption key. It changes every epoch and is not forward-secure, so the evs keys sit above it (§10.5).
- **Lost.** A forward-secure export. DESIGN.md does not say what would use one.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** The draft settles; then a design for which secrets move to it and how a group changes over.

<a id="keys-gen-packs"></a>
### Gen packs

*Later, at §19.9's gen trigger. DESIGN.md: §10.16, §19.18, §23.4.*

- **Deferred.** Packing a group's old generation objects: taskworker writes `gkm/<group_id>/genpack/<k>`, holding 256 generations verbatim, once 64 newer generations exist, then deletes those objects; a read falls back from a `gen/` 404 to the pack (§10.16, §19.18, §23.4; D-KEYS-20; Q-OPS-2; QD-401).
- **Why.** They are not in this build and have no task or FS row (QD-401). They start on a cluster only at §19.9's gen trigger, which is projected from §22.8's M2 count.
- **Launch instead.** Every generation is its own `gen/` object for the repo's life (D-KEYS-20).
- **Lost.** Nothing until the trigger.
- **Dark in code.** Nothing is built. Gen reads go through one accessor, so the fallback to a pack has one place to go (the plan's KEYS-M2-15).
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** §19.9's gen trigger on a cluster. M2's exit raises it if §22.8's M2 count projects the trigger within a year. Then build §10.16's rules: packs count as `gen/` for shreds, their 10-minute repeat and re-seeds, hold no slot, and no claim lands at or below a pack.

<a id="keys-v1"></a>
### §10's v1 set

*v1 (M6, M10). DESIGN.md: §10.16.*

- **Deferred.** §10.16's v1 row: the Team audit reader (owner decision 63); with Team at M6, the config group's wraps for member devices past the first 1,000 (owner decision 144) and the team directory's group (owner decision 182); at M10 (owner decision 169), the `index` purpose with the search index (owner decision 163) and format 2's one slot key per versionless path.
- **Why.** Team ships at M6 and format 2 at M10.
- **Launch instead.** v0's key management at M2: all of §10.4 to §10.9 but these and MLS, every group key going by wraps (owner decision 610), with `directory` already among `ur_group`'s kinds.
- **Lost.** Until M6: the audit reader and large teams' wraps. Until M10: index keys and slot keys.
- **Dark in code.** Built in the same run on the `sidecar` branches.
- **Held.** Nothing.
- **To bring back.** Nothing to bring back: each ships when its milestone's gate passes (§23.6).

<a id="s11"></a>
## §11 Encrypted versioned storage: format, git service, head API, subscriptions

<a id="evs-compaction"></a>
### Compaction

*Later. DESIGN.md: §11.22, §23.4.*

- **Deferred.** Compaction of packs, parcels and batches: rewriting them without the records that erasure or a drop left unreadable (owner decision 247; QD-053; §11.7, §11.12, §11.13, §20.6, §20.7; §2.8's evs-4 and evs-12; §23.4).
- **Why.** §11.22 once listed compaction for v1, but no row specified it, and §11.8 deletes packs only whole, so it would be a new deletion path. Designing it for v1 meant new design and peer review before M6's entry and a rewrite of immutable packs, in the costliest bug class.
- **Launch instead.** Erased and dropped inline ciphertext and packed segments stay stored, unserved and unreadable once their keys are gone, "until a later compaction, unscheduled". A drop's job deletes whole objects only (§11.13).
- **Lost.** Those bytes count against the repo's storage, and are billed, for the repo's life.
- **Dark in code.** Nothing is built. §22.8's drop row expects a pack to keep its dropped records, since compaction is Later.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design for rewriting an immutable container under §11.8's commit rules and under holds, its peer review, an owner decision, and new wording for evs-4's and evs-12's ttl.

<a id="evs-expired-ciphertext-reclaim"></a>
### The reclaim of expired ciphertext

*Later. DESIGN.md: §11.22, §23.4.*

- **Deferred.** A GC that deletes a record-class repo's expired segments after retention erases their keys (owner decision 246; QD-047; §11.13's gc row, §16.8; §2.8's evs-4; §23.4).
- **Why.** §11.13's row deleted "segments no retained push names" while every push statement stays, so read literally it deleted nothing, and no section defined "retained". Building it at M6 meant a scan like the drop job's before M10 proves one, in the costliest bug class.
- **Launch instead.** Retention at M6 is expiry, ERASE and BASE: keys are erased and the live set re-listed. The expired ciphertext stays, keyless, "until a later GC, unscheduled". What M2 does delete is defined: a deposit's version is retained until a committed CONSUME removes it, and its segments go 7 days later once no other version names them.
- **Lost.** A record-class repo's expired segments stay stored and billed for the repo's life, unreadable.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** Owner decision 246 gives its shape: 7 days after a BASE, delete only segments that no entry of the live set and no later version names, by a mark and verify like the drop job's, under holds. It needs that design written out, its FS row, and evs-4's ttl reworded.

<a id="evs-working-tree-sync"></a>
### Working-tree sync

*Later. DESIGN.md: §11.22, §23.4.*

- **Deferred.** Working-tree sync, which §11.22's v1 list once named (owner decision 250; QD-276).
- **Why.** No section said what it is: it had no requirement, row or test. R-EVS-9 and §11.11 cover a bare repository and stock git only.
- **Launch instead.** A git user updates a working tree with stock git against the local git server (§11.11).
- **Lost.** Nothing that was specified.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** The owner says what it is; if cli/UI.md turns up with a requirement, the owner reads it first. Then a design for dirty trees with its own tests.

<a id="evs-derived-shares"></a>
### Derived shares

*Later. DESIGN.md: §11.22, §23.4.*

- **Deferred.** "Derived shares", which §11.22's v1 list once named and no other section mentions (owner decision 250; QD-276).
- **Why.** No section says what a derived share is, and nothing depends on one.
- **Launch instead.** Shares are `EvsShare` statements on a repo (§8.8) and, across networks, §17.9's IP path.
- **Lost.** Nothing that was specified.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** The owner says what a derived share is; then it is designed as a new item.

<a id="evs-sha256-object-format"></a>
### Git's SHA-256 object format

*Later. DESIGN.md: §11.11, §11.22.*

- **Deferred.** Mounting or importing a repository that uses git's sha256 object format (owner decision 249; QD-237; §11.6, §11.11).
- **Why.** Supporting both from v0 meant a second hash through the local tier, hooks, export, the mobile and wasm git codec, vectors and §22.9's matrix.
- **Launch instead.** SHA-1 only. The daemon creates its bare repository with `--object-format=sha1`, and `ur mount add`, `ur evs import` and `git-remote-ur` refuse a sha256 repository, naming it, before any evs write.
- **Lost.** A sha256 repository cannot be mounted. That will bite once Git 3.0 makes sha256 the default for new repositories.
- **Dark in code.** The width is reserved: format 1 carries a 32 B oid and `oid_kind`, so adding sha256 needs no format change.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A second `oid_kind`, the hash through the local tier, hooks, head mode's codec and export, new vectors, and the sha256 column of §22.9's git matrix.

<a id="evs-mobile-full-sync"></a>
### Full sync on mobile

*Later. DESIGN.md: §11.22.*

- **Deferred.** A phone holding a full-sync copy of a repo, named in §11.22's Later row. It has no D- item, task or FS row.
- **Why.** DESIGN.md gives no reason beyond the Later row. R-EVS-14 holds evs to 4 MiB in the iOS app process.
- **Launch instead.** Mobile and wasm hosts read in head mode, read both ref modes and write only file-mode refs; a mobile catch-up fetches at most 4 MiB of statements and proofs (§11.7, §11.9).
- **Lost.** A phone is not a full-sync device, so it cannot do what needs every name of a ref unless it mirrors that ref.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design for the sync engine within a phone's memory and storage, storage over RAM, and an app that asks for it.

<a id="evs-state-commitment"></a>
### A state commitment over the token tree

*Later, if measurements ask for it. DESIGN.md: §11.22.*

- **Deferred.** A commitment over a ref's whole state, which would give a head reader freshness for paths older than its pin (§11.22; Q-EVS-6; owner decision 209's option (3), not taken).
- **Why.** The peer review closed Q-EVS-6 without a Merkle root: head readers replay signed statements from their pin and check the statement behind every entry they read. Owner decision 209 declined to reopen that before M2's freeze.
- **Launch instead.** Q-EVS-6's answer (c), made cheap (§11.9, D-EVS-24), and a sealed record of each path a head reader has read, at most 16,384 a network (owner decision 209): a recorded path served below its record is refused and alarmed.
- **Lost.** Pre-pin freshness for a path the reader never read or no longer remembers: evs could serve it at an older committed version from before the reader's pin, unseen. §2.8 publishes that limit.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** Measurements showing that head readers need pre-pin freshness, then a design for the commitment and its cost on each head write, and a format change after the freeze.

<a id="evs-directory-resident-children"></a>
### Directory-resident children

*Later, if §22.8 shows the need. DESIGN.md: §11.22.*

- **Deferred.** Keeping an append-only record directory's children inside the directory's own object, paged, through the reserved `layout` (§11.7's directory row; §11.22).
- **Why.** It is worth its cost only if §22.8 shows stream entries' index objects binding.
- **Launch instead.** Each child has its own index object; a directory holds at most 4,096 children and 448 KiB of name table, and §15 and §16 shard their streams by sequence under that bound.
- **Lost.** Nothing unless the measurement binds: then a stream's index objects cost more metadata-cluster writes and inodes than a resident layout would.
- **Dark in code.** `layout` is reserved in format 1 (sidecar/protocol/evs.proto), so the layout needs no new field.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** §22.8's count of stream entries' index objects, then a design for the paged layout and a storage-format step.

<a id="evs-repo-move-tool"></a>
### A tool that moves placed repos between clusters

*Later, before the first cohort exhaustion. DESIGN.md: §10.16, §11.22, §19.18, §23.4.*

- **Deferred.** A tool that moves a repo, with its gkm group, from the metadata cluster it was placed on to another, keeping one commit point (owner decision 145; §10.16, §11.22, §19.18, §23.4; Q-OPS-10's residual).
- **Why.** Owner decision 145 grows the metadata tier by whole clusters, places each repo once at creation, and names the move tool a later item.
- **Launch instead.** A repo stays on the cluster placed at its creation. New repos go to the next cluster from §19.9's triggers, and §11.13's write budget refuses the heaviest network first.
- **Lost.** An existing repo cannot be moved off a full cluster, so the first cluster's writes can outgrow its set (§3.14's and §11.21's risk rows). A cluster that fills answers 507 CLUSTER_FULL.
- **Dark in code.** Nothing is built. `place/` never moves.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** §19.9's cohorts row projects each cluster's exhaustion, and the tool is built to land before the earliest one. It needs a design that moves `place/`, the repo's metadata objects and its gkm group while a single commit point holds.

<a id="evs-per-cluster-batcher"></a>
### A per-cluster batcher

*Later, if §22.8 shows it saves a set. DESIGN.md: §11.22.*

- **Deferred.** Two evs processes batching each cluster's records together, near 5 records a batch (§11.21's risk row; §11.22; §19.17).
- **Why.** It is worth building only if §22.8 shows that it saves a drive set.
- **Launch instead.** Each evs process batches its own records (§11.8). §22.8's M2 gate measures records per batch per cluster.
- **Lost.** Nothing unless the measurement shows small batches: then drive writes per push are higher than a shared batcher would give, and the next cluster is needed sooner.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** §22.8's records-per-batch figure on production load, then a design for routing a cluster's pushes to two batching processes.

<a id="evs-reverse-citation-index"></a>
### A reverse citation index in pidx/

*Later, if §22.8 shows scans binding. DESIGN.md: §11.22.*

- **Deferred.** An index from each segment to the versions that cite it, kept in `pidx/` at evacuation, so a drop's scan reads `pidx/` only (§11.16's alternatives row; §11.22).
- **Why.** §11.16: it is a permanent NVMe cost on every push for a rare action.
- **Launch instead.** The drop job scans to find what still cites a segment (§11.13).
- **Lost.** Nothing unless §22.8's `drop` row shows the scans binding: then drops run slower than they could.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** §22.8's `drop` row showing the scan as the limit, then the index, its write on every evacuation, and its rebuild for existing repos.

<a id="evs-index-semantic-layer"></a>
### A word complement or semantic layer in the search index

*Later. DESIGN.md: §11.22.*

- **Deferred.** A word complement or a semantic layer stored in the search index's own buckets, named in §11.22's Later row. It has no D- item, task or FS row.
- **Why.** DESIGN.md gives no reason beyond the Later row.
- **Launch instead.** A trigram index: each document's set of distinct 24-bit keys over its normalized text, searched on the device (§11.14).
- **Lost.** Search matches text by trigrams only: no ranking by meaning and no whole-word postings.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design for the layer's keys and for what it lets evs infer, then an index-format step. See also semantic search in §16's entries.

<a id="evs-index-elias-fano-key-sets"></a>
### Elias-Fano key sets

*Later. DESIGN.md: §11.22.*

- **Deferred.** Encoding the search index's key sets as Elias-Fano, named in §11.22's Later row. It has no D- item, task or FS row.
- **Why.** DESIGN.md gives no reason beyond the Later row.
- **Launch instead.** Key sets in §11.14's encoding, which protocol/INDEX-FORMAT.md fixes.
- **Lost.** Whatever bytes or decode time Elias-Fano would save; DESIGN.md gives no figure.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A measurement against the current encoding, then an index-format step.

<a id="evs-index-per-field-postings"></a>
### Per-field postings

*Later, if §22.8 shows field-scoped queries common. DESIGN.md: §11.22.*

- **Deferred.** A posting set for each field of a document, in place of one set for all fields (§11.14's fields row; §11.22).
- **Why.** One posting set gives 12.6 to 17.3% less index, and a field-scoped query is confirmed against the doc table row, which costs nothing for header fields.
- **Launch instead.** One posting set covers every field.
- **Lost.** A field-scoped query over body text does more confirming work on the device.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** §22.8 showing that field-scoped queries are common, then an index-format step.

<a id="evs-slot-orphan-pass"></a>
### A pass that collects orphaned slot objects

*Later. DESIGN.md: §11.22.*

- **Deferred.** A pass over `slot/` that removes a slot object no record names (§11.8's step 6; owner decision 400; DESIGN-DETAILS.md section 14).
- **Why.** DESIGN-DETAILS.md section 14: the pass is not designed, and nothing rests on it.
- **Launch instead.** A crash between a slot's creation and its record leaves at worst a slot that no record names. The same statement's retry takes it; otherwise it stays, at most 8 KiB.
- **Lost.** A few stray objects of at most 8 KiB each, stored for the repo's life.
- **Dark in code.** Each slot object carries the statement that created it as its origin, in object metadata, which is what such a pass would read.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design: remove a slot that carries an origin and no hold once Resolve finds its origin's statement dead and the evacuation horizon has passed the minute its record could lie in.

<a id="evs-v1"></a>
### §11's v1 set

*v1 (M6, M10). DESIGN.md: §11.22.*

- **Deferred.** §11.22's v1 row: retention as expiry, ERASE and BASE (owner decision 246); agent-subkey provenance; the `directory` kind at M6 on format 1's streams. Format 2 at M10 (owner decision 169): versionless files with staging, the purge and its sweep, rules and the repo lock, migration and the git-lfs store; the search index with its erasure cut and erasure sets; the directory's cards and index; the drop-history action behind §19.11's `format2.drop` gate; remote search.
- **Why.** Team ships at M6 and format 2 at M10 (owner decisions 55, 163, 169).
- **Launch instead.** Format 1 (v0a) with the local tier (v0b), both at M2. Format 1 reserves format 2's numbers and refuses data that uses them as FORMAT_UNSUPPORTED.
- **Lost.** Until M6: retention and the directory. Until M10: versionless files, search and drops.
- **Dark in code.** Built in the same run on the `sidecar` branches. §19.11's `format2` gate, with its purge and drop modes, holds format 2 to internal networks and design partners first.
- **Held.** Nothing.
- **To bring back.** Nothing to bring back: each ships when its milestone's gate passes (§23.6).

<a id="s12"></a>
## §12 DNS: the ur.network zone and per-network zones

<a id="dns-psl-listing"></a>
### The Public Suffix List listing and the mail cut-over

*Later, once eligible. DESIGN.md: §12.16, §13.17, §14.16, §15.17, §23.4.*

- **Deferred.** Listing `<root>` on the Public Suffix List, and after it §14.6's cut-over of burner mail's DMARC alignment (D-DNS-1's step 5; owner decisions 13 and 79; §12.4, §12.16, §13.17, §14.6, §14.16, §15.17, §23.4; D-SMTP-5).
- **Why.** The list has entry conditions the root does not meet yet: about 3,000 active users, the `_psl` proof record and an abuse contact, with over 2 years of registration term at listing.
- **Launch instead.** The root is renewed to 2036 at M0 and keeps the `_psl` proof record (§12.4). Until the listing, every network under `<root>` shares one site (cookies, saved logins), one reputation, one Let's Encrypt budget and one DMARC organization. DMARC alignment stays strict, and each replying or forwarding burner publishes selectors of its own (owner decision 79).
- **Lost.** Browser and mail isolation between networks' names: a cookie or a reputation hit on one label reaches all. A burner's aggregate reports do not reach its network's own token until the listing (§14.8).
- **Dark in code.** Nothing is switched off. The root zone carries `_psl`, and the application is an outward step the owner takes.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** The root reaches the list's conditions; the owner applies and asks for recategorization. Then §14.6's test: a test network's burner mail, signed only under its network selector, passes DMARC at Gmail, Outlook.com and Yahoo. Each `_dmarc.<net>.<root>` then switches to relaxed alignment, burners sign with the network's selectors, and 7 days later §12 deletes the per-burner selectors and records.

<a id="dns-bring-your-own-ns"></a>
### Bring-your-own nameservers

*Later. DESIGN.md: §12.16.*

- **Deferred.** A network delegating its names to nameservers of its own, named in §12.16's Later row. It has no D- item, task or FS row.
- **Why.** DESIGN.md gives no reason beyond the Later row.
- **Launch instead.** The dns edge serves every name under `<root>`, and user records refuse NS (§12.7's refused row). A Team's own domain comes at M6 as a custom domain, verified and pointed at the edge (§12.8).
- **Lost.** A network cannot run its own DNS for names under `<root>`.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design for delegation: what a child zone may hold, DNSSEC across the cut, and how abuse controls reach names the edge no longer serves.

<a id="dns-https-svcb-records"></a>
### HTTPS and SVCB records

*Later. DESIGN.md: §12.16.*

- **Deferred.** HTTPS and SVCB records for user names (§12.7's refused row; §12.16).
- **Why.** §12's refused row: there is no ECH or h3 for them to announce (§13).
- **Launch instead.** User records refuse HTTPS and SVCB; clients find the edge by A and AAAA records on TCP 443.
- **Lost.** Nothing until ECH or h3 exists at the edge.
- **Dark in code.** Nothing is built: the record types are refused.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** ECH split mode or h3 at the edge (§13's entries), then the record types and what they publish.

<a id="dns-mta-sts-certificate-gate"></a>
### `_mta-sts` waiting for every receiver's certificate

*Review phase, once §13's issuance for receivers settles. DESIGN.md: §12.7, §15.5.*

- **Deferred.** The certificate condition on §12.7's `_mta-sts` record: the record is published only while every published `mail_host_key` row for host `mx` has an unexpired certificate on the same key, a certificate's issuance and a host-key change each reconciling the zone (§15.5's MTA-STS; owner decision 630, whose answer takes this part of the question's option 1 at the review phase; ledger id QD-1092).
- **Why.** The verified gate is what owner decision 96 names and is cheap to hold now. The per-key join waits for the receivers' issuance path (the plan's TLS-M8-01) to settle, since it adds two callers of the zone's reconcile on that path.
- **Launch instead.** `_mta-sts` is published for a network with network_verified and mail on, and a verification change reconciles the zone (§12.7). Each receiver serves the policy only once it holds its own §13 certificate (§15.5).
- **Lost.** While one of a network's receivers is still uncertified, a sender that cached the `mode: enforce` policy refuses that receiver (RFC 8461 §5): some deliveries fail temporarily, until the router's backup ticket or the sender's retry reaches a certified receiver. A receiver is certified minutes after its key is posted.
- **Dark in code.** Nothing is built. The zone's mail policy is computed in one place, where the condition joins.
- **Held.** The review phase's two reconcile callers, at a receiver certificate's issuance and at a host-key change.
- **To bring back.** The receivers' issuance path settles; then the zone's mail policy takes the per-key certificate condition, the two write paths call the zone's reconcile, and a test shows the record withheld while one receiver is uncertified.

<a id="dns-v1"></a>
### §12's v1 set

*v1 (M6, M7, M8). DESIGN.md: §12.16.*

- **Deferred.** §12.16's v1 row: aliases, custom domains in both CAA modes and Team scopes at M6; direct MX and strict-mode MX hosts at M7; scope mail hosts with §15 at M8.
- **Why.** They are Team items (owner decisions 33, 55, 58).
- **Launch instead.** v0's zone: labels, edge, challenge, SPF, DMARC, null MX and user records at M5; mail records, TLSA and the DS at M7; replying burners' selectors and the reverse zones' PTRs at M9.
- **Lost.** Until those milestones: a Team's own domain, aliases and scope hosts.
- **Dark in code.** Built in the same run on the `sidecar` branches. §13.4's generated split map blocks M6's custom hosts.
- **Held.** Nothing.
- **To bring back.** Nothing to bring back: each ships when its milestone's gate passes (§23.6).

<a id="s13"></a>
## §13 The TLS edge and certificates

<a id="tls-ech-split-mode"></a>
### ECH in split mode

*Later. DESIGN.md: §2.19, §13.17.*

- **Deferred.** Encrypted ClientHello at the edge, in split mode, so the name a visitor asks for is hidden on the path (§2.19, §13.17; D-TLS-10).
- **Why.** D-TLS-10: ECH routing needs split mode, which Go's TLS server lacks.
- **Launch instead.** tlsedge routes on the cleartext SNI, publishes no ECH configs and ignores GREASE ECH (§13.5). §2.8 lists the SNI and the whole ClientHello among what the lb and tlsedge see.
- **Lost.** The host name of every TLS connection to the edge is visible to the network path, as well as to the edge.
- **Dark in code.** Nothing is built. The ClientHello parser reads ECH presence only (sidecar/tlsedgeservice).
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** Split-mode ECH in the TLS stack tlsedge uses, a design for the public name and key rotation, HTTPS records to publish the configs (§12's entry), and new §2.8 words.

<a id="tls-h3-edge"></a>
### HTTP/3 on the edge's UDP 443

*Later. DESIGN.md: §13.17.*

- **Deferred.** h3 on edge UDP 443 (§13.17; D-TLS-10).
- **Why.** D-TLS-10: a QUIC connection's SNI cannot be preread while connect owns UDP 443.
- **Launch instead.** TCP 443, 8443, 8883 and 5671. The front serves no HTTP/3 and strips upstream `Alt-Svc` h3 entries (§13.7).
- **Lost.** No HTTP/3 to a published name.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A way to split UDP 443 between connect's transport and the edge by QUIC's SNI, then QUIC in tlsedge's connection path and its metering.

<a id="tls-anycast"></a>
### Anycast for the edge

*Later. DESIGN.md: §13.17.*

- **Deferred.** Anycast addresses for the edge, named in §13.17's Later row. It has no D- item, task or FS row.
- **Why.** DESIGN.md gives no reason beyond the Later row. There is one lb site today (§9.17).
- **Launch instead.** The edge shares the existing lb addresses through the SNI split on TCP 443 (§13.4; owner decision 34).
- **Lost.** Nothing while there is one site.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A second site and address space to announce, which is an operations and provider change before it is a design one.

<a id="tls-v1"></a>
### §13's v1 set

*v1 (M6). DESIGN.md: §13.17.*

- **Deferred.** §13.17's v1 paragraph: Team custom domains, with §12's custom-host-add, the split's custom-host map and strong-mode CAA checks (FS-32, FS-35, FS-122); Team scopes; affinity; `members-device`; overlay access for members by §17's maps and grants, with M6's `ur tun` on macOS and Windows; publish reach receipts (§16).
- **Why.** They are Team items (owner decision 55).
- **Launch instead.** v0 at M5: the SNI split with an empty custom-host map, tlsedge and Service contracts, certificates under `<root>`, the front with `members` login, desktop `ur bridge public-tls`, and the CT watch.
- **Lost.** Until M6: a Team's own domains and member-device access.
- **Dark in code.** Built in the same run on the `sidecar` branches.
- **Held.** Nothing.
- **To bring back.** Nothing to bring back: it ships when M6's gate passes (§23.6).

<a id="s14"></a>
## §14 The SMTP edge: outbound mail and abuse attribution

<a id="smtp-designated-verifier-prover"></a>
### A designated-verifier prover

*Later. DESIGN.md: §14.16, §23.4.*

- **Deferred.** A designated-verifier (VOLE) prover for the proofs of TLS delivery, so that phones can prove and DATA mode carries megabytes a message (§14.15's risk rows; §14.16; §23.4).
- **Why.** DESIGN.md gives no reason beyond the Later rows. M9's gate is the proofs as designed: sound BDAT and DATA circuits, working and fast enough (owner decisions 35, 99, 125).
- **Launch instead.** M9's prover runs on a member's prover hosts, never on a phone: a phone writes its mailbox outbox and a prover host sends it (D-SMTP-18). A message goes in one-record parts, each proving within 2 minutes. DATA mode proves minutes per 100 KiB, so a message above `smtp_data_proof_bytes`, about 3 MiB on an M1, to an MX without CHUNKING gets a DSN, and `Check` and the `too_large` outcome name the size, the cap and the domain.
- **Lost.** A member with only phones sends no internet mail; an MX without a covered TLS version or suite gets none; and DATA-mode mail to an MX without CHUNKING is slow and capped (§14.15's risk rows).
- **Dark in code.** Nothing is built. `SmtpProver` (sidecar/smtp_proof.go) is the one seam a new prover replaces.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design for the designated-verifier scheme, what the edge then holds as verifier and what §2.8 publishes, its soundness review under the gate owner decision 35 set, and a second implementation behind `SmtpProver`.

<a id="smtp-dkim2"></a>
### DKIM2

*Later. DESIGN.md: §14.16.*

- **Deferred.** DKIM2, named in §14.16's Later row. It has no D- item, task or FS row.
- **Why.** DESIGN.md gives no reason beyond the Later row.
- **Launch instead.** DKIM with per-sidecar RSA-2048 keys and opaque selectors that rotate every 90 days (§14.6; owner decision 36).
- **Lost.** DESIGN.md does not say.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** The standard settles and receivers adopt it; then a design for signing under it beside DKIM.

<a id="smtp-v1"></a>
### §14's v1 set

*v1 (Team, from M9). DESIGN.md: §14.16.*

- **Deferred.** §14.16's v1 row: sending from a Team's custom domains.
- **Why.** Custom domains are a Team item (owner decision 55), and sending starts at M9.
- **Launch instead.** v0 at M9 sends from `<net>.<root>` under §14.6's identity.
- **Lost.** Until then a team sends only from its network's name under `<root>`.
- **Dark in code.** Built in the same run on the `sidecar` branches.
- **Held.** Nothing.
- **To bring back.** Nothing to bring back: it ships with M9's gate and M6's custom domains (§23.6).

<a id="s15"></a>
## §15 The local email server, inbound mail, and burner email

<a id="mail-destination-routing"></a>
### Destination routing on a routed IPv6 block

*Later, if a routed IPv6 block is obtained. DESIGN.md: §15.17.*

- **Deferred.** Routing inbound mail by destination address, which would restore a fallback for senders that send no SNI (owner decision 34; §15.17).
- **Why.** The owner's constraint (owner decision 34): "There are no dedicated ipv4 or ipv6 options currently."
- **Launch instead.** Inbound routing is SNI and DANE only, on the shared lb addresses. M7's census measures which senders send no SNI, and the owner accepts that loss before the burner launch (D-MAIL-9).
- **Lost.** Mail from senders that send no SNI is not delivered; the census sizes it.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A routed IPv6 block from the transit provider, then per-network addresses in §12's records and a route in mxedge.

<a id="mail-team-burners"></a>
### Team burners

*Later. DESIGN.md: §15.17.*

- **Deferred.** Burner addresses for Team networks, named in §15.17's Later row. It has no D- item, task or FS row.
- **Why.** DESIGN.md gives no reason beyond the Later row. BS1, the burner launch, is on personal networks.
- **Launch instead.** Burners on personal networks from M8, replies from M9. Team networks get admin, id, group and agent addresses, and scopes.
- **Lost.** A team member has no burner under the team's network.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design for who owns a team burner, where its vault entry lives, and how §21's limits count it.

<a id="mail-edge-reputation"></a>
### Edge reputation from receiver verdicts

*Later. DESIGN.md: §15.17.*

- **Deferred.** Scoring senders at the edge from receivers' verdicts, named in §15.17's Later row. It has no D- item, task or FS row.
- **Why.** DESIGN.md gives no reason beyond the Later row.
- **Launch instead.** mxedge's banner rejects only a commercial feed's botnet and exploit listings and passes other listings on to the receiver (§15.4); the receiver's device verifies SPF, DKIM, DMARC and ARC and scores each message itself (§15.5).
- **Lost.** What one receiver learns about a sender does not protect another.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design for what a receiver reports, since a verdict is new server-visible metadata and needs a §2.8 row first.

<a id="mail-named-credentials"></a>
### Several named mail credentials per network

*Later. DESIGN.md: §15.10.*

- **Deferred.** Several named verifiers per network for IMAP and submission, each made and revoked on its own as app passwords are, with `ur mail credential ls` and `rm` (owner decision 442's option 4; QD-859; §15.10).
- **Why.** Owner decision 442 takes option 1 now and option 4 later.
- **Launch instead.** One credential per network. `ur mail credential` shows its secret once, and the daemon keeps only a verifier.
- **Lost.** A person with two mail clients saves the secret when it is shown, or makes a new one and enters it in each client. One client's credential cannot be revoked alone.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A list of named verifiers in the network's keychain, the two commands, and LOGIN's constant-time compare over every verifier.

<a id="mail-v1"></a>
### §15's v1 set

*v1 (M7, M8, M10). DESIGN.md: §15.17.*

- **Deferred.** §15.17's v1 rows. Team (owner decisions 33, 58, 98, 150): network-scope mail indexers, direct MX and strict mode from M7, scopes from M8. M10 (owner decision 169): mail search (D-MAIL-16), IMAP SEARCH on the engine, and phones' remote search over mail.
- **Why.** Team ships at M6 and search at M10.
- **Launch instead.** v0: the platform listener at M5, network mail at M7, burners and IMAP at M8, sending at M9.
- **Lost.** Until those milestones: a team's shared receivers and strict mode, and search over mail.
- **Dark in code.** Built in the same run on the `sidecar` branches.
- **Held.** Nothing.
- **To bring back.** Nothing to bring back: each ships when its milestone's gate passes (§23.6).

<a id="s16"></a>
## §16 The local MCP server, harness integration, and record primitives

<a id="mcp-team-legal-holds"></a>
### A team's own legal holds

*Later, with RS3's assurance stage. DESIGN.md: §16.18, §23.4.*

- **Deferred.** A hold that a team places on its own records, which suspends retention's expiry (§16.8, §16.18; §23.4's RS3).
- **Why.** It belongs to RS3, recURd's assurance stage, which ships whole once its assurance items land (R-PHASE-4).
- **Launch instead.** Retention expires entries as its policy says. The only hold is §21.9's preservation hold, which URnetwork places on legal process and which pauses server-side GC.
- **Lost.** A team under a hold of its own cannot suspend its record's expiry.
- **Dark in code.** Nothing is built. §21.9's preservation holds are a separate, in-scope mechanism.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design: who places and lifts a team hold, a signed statement for it in the config repo, how every eraser's device honors it, and its FS row.

<a id="mcp-regex-queries"></a>
### Regex queries

*Later. DESIGN.md: §16.18.*

- **Deferred.** Regular-expression queries in `ur search` and the search tools, planned as codesearch's planner does over trigrams (§16.10's query row; §16.18).
- **Why.** §16.10: "no regex in v1". DESIGN.md gives no further reason.
- **Launch instead.** Each word or quoted phrase is a required substring term, with OR, exclusion, `field:text` and `fuzzy` (§16.10).
- **Lost.** No pattern search over indexed text.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A regex-to-trigram planner on the device, limits on what a pattern may cost, and a `search_version` step for remote search.

<a id="mcp-semantic-search"></a>
### Semantic search and embedding

*Later. DESIGN.md: §3.6, §16.18, §23.4.*

- **Deferred.** Semantic search on desktops and indexers, and embedding as an indexer service (owner decision 150; R-CTX-33; §3.4, §16.18, §23.4).
- **Why.** Owner decision 150 names embedding as future work for an indexer. DESIGN.md gives no design for it.
- **Launch instead.** §11.14's trigram index and §16.10's substring search, with fuzzy near hits.
- **Lost.** Search by meaning.
- **Dark in code.** Nothing is built. `IndexerSet`'s readers ignore a service value they do not know (the plan's TEAM-M2-07), so a later `embedding` service does not break an older device.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design: where the model runs, what an embedding reveals if it is stored, where vectors live in evs, and a new `IndexerSet` service.

<a id="mcp-transcript-text-index"></a>
### Transcript text in the vault's index

*Later, once §22.8 measures it. DESIGN.md: §16.18.*

- **Deferred.** Indexing every capture entry of a run, tool calls and transcripts included (§16.12's alternatives row; §16.18).
- **Why.** §16.12: it indexes tool output, much of it outside text, at near the runs' own size.
- **Launch instead.** The vault's index holds run cards: title, prompts, tool names, touched paths and times (§16.7, §16.10).
- **Lost.** A search does not find a run by text that appears only inside its transcript or a tool's output.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** §22.8's measurement of the index's size and write cost with transcripts in it, then a document class for capture entries.

<a id="mcp-worker-task-delegation"></a>
### Delegating tasks to a worker's agent and sharing its run sessions

*Later. DESIGN.md: §16.18, §23.4.*

- **Deferred.** Handing a task to another member's worker agent, and sharing that worker's run sessions (owner decision 179; Q-MCP-8; §16.18, §23.4).
- **Why.** Owner decision 179: in v1, access to a worker means reaching the services it announces; delegating tasks and sharing sessions are later items, each with a design of its own.
- **Launch instead.** An approved request through the directory becomes a grant to dial the ports, sockets and published names the worker announces, under the access policy, with an approver, an expiry and receipts (§16.11).
- **Lost.** One member's agent cannot ask another's to do work, or watch its session, through the directory.
- **Dark in code.** Nothing is built. The plan keeps the worker items of the directory's access requests (RECORD-M6-17) as the seam.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** Two designs, one each: what a delegated task may do and under whose approvals, and who may read a shared session.

<a id="mcp-sealed-requests"></a>
### Directory requests sealed to their approvers

*Later. DESIGN.md: §16.18.*

- **Deferred.** Sealing a directory request to its approvers, so other members see no request and there is no per-target prefix (§16.11's cost paragraph; §16.12's alternatives row; §16.18).
- **Why.** §16.12: it needs per-approver HPKE, fixes the approver set at filing, and makes audit harder.
- **Launch instead.** Requests are entries in the team directory, which every admitted sidecar of the team reads.
- **Lost.** Every member, and every agent of the team, can see who asked for access to what.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design for sealing to a set of approvers that changes after filing, and for the audit reader's view.

<a id="mcp-directory-guest-view"></a>
### A guest view of the directory for cross-network shares

*Later. DESIGN.md: §16.18.*

- **Deferred.** Letting a guest from another network see a team's directory (§16.12's alternatives row; §16.18; QD-268).
- **Why.** §16.12: no cross-network evs read exists in v1. Cross-network shares are §17.9's IP path, for which evs builds nothing.
- **Launch instead.** A guest reaches what a share grants over §17.9's IP path. The directory is read by the team's own sidecars only.
- **Lost.** No discovery across networks.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A cross-network evs read first, which is a design of its own, then a view limited to what the guest was granted.

<a id="mcp-member-prose-setting"></a>
### A per-team setting for prose at member trust

*Later. DESIGN.md: §16.12.*

- **Deferred.** A per-team setting that would give agents the prose of directory announcements, requests and decisions at `member` trust (§16.12's alternatives row; D-MCP-29).
- **Why.** D-MCP-29 rejects it as the default: auto-filed text would be broadcast to every agent with no person reading it (I-9; owner decision 142). The setting is left for later.
- **Launch instead.** Directory prose is untrusted. Agents get stubs of attested and identifier fields, and prose only with `untrusted: include`, which taints the run first.
- **Lost.** Richer coordination between agents through free text.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design for who may turn it on and what an injection then costs, and an owner decision against I-9's rule.

<a id="mcp-harness-config-keys"></a>
### The harness config's waiting keys

*Later. DESIGN.md: §8.5, §16.7.*

- **Deferred.** Four keys of the global harness config: `record.capture` as a narrowing control, and `reach`, `models` and `identity`; with them §8.5's harness `reach:` block as a filer of access requests (owner decision 452; QD-116; §1's source row; §8.5, §16.7).
- **Why.** Owner decision 452: a narrowing control on capture weakens R-MCP-4 and needs a person-only surface first. The other three wait for a later design.
- **Launch instead.** Two keys act: `record.redact.pii` from M3 and `claims` from M6, with `agents.<label>` overriding those two only. Capture stays §16.7's fixed set.
- **Lost.** A person cannot narrow what is captured, and a harness config cannot file reach requests, choose models or set identity.
- **Dark in code.** The keys are kept in the format: `record.capture` is read and ignored, and `reach`, `models` and `identity` are ignored and warned about, so a `reach:` block files no request.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design for each key. For capture: a person-only path and a Team refusal. For `reach`: how a block becomes requests under §8.5.

<a id="mcp-sshsig-approvals"></a>
### SSH-signed approvals for high-risk actions

*Later, until a customer asks. DESIGN.md: §16.6, §16.18.*

- **Deferred.** The member's SSHSIG on a high-risk approval, and with it a second risk level: a classifier or a policy field that marks an action high risk, and SSH-signed receipts (R-MCP-7; §16.6's approval channels; owner decision 279, which declined the build's recommendation of two risk levels; ledger id QD-014; the plan's MCP-M4-03).
- **Why.** §16.6 added the SSHSIG to a high-risk approval, and nothing said what makes an action high risk or who computes it. The owner dropped it from v0 and every milestone until a customer asks (owner decision 279).
- **Launch instead.** Every action's risk is normal. A decision carries its evidence channel, device, presence or harness, and a network's `requests` rules and `evidenceDefault` say which channels it accepts (§16.6, §8.5).
- **Lost.** No second factor separates a public publish or a wide mailing from any other approved action.
- **Dark in code.** `ApprovalDecision.sshsig` stays a reserved field, ignored wherever it is presented and never trusted; `SidecarRisk` keeps its two values, every action normal, and no policy field or classifier raises one (§16.8, §5.4). `KeyRegister` still takes a key of purpose `KEY_PURPOSE_SSHSIG` (§7.9), which nothing verifies a decision under.
- **Held.** MCP-M4-03, the plan's task for the SSHSIG on high-risk decisions, is void while this stands.
- **To bring back.** A customer asks. Then an owner decision on what makes an action high risk, a fixed classifier, a policy field on request rules or both, as owner decision 279's options not taken describe; `AclRequestRule` gains its risk field, and verifiers check the SSHSIG under the member's registered key.

<a id="mcp-card-closure-replay-check"></a>
### The fresh-reader check on a directory admin's CLOSURE of a card or repo file

*Review phase. DESIGN.md: §16.11.*

- **Deferred.** A reader-side check that holds a directory admin's push at a `d/` or `r/` path to the `cards` ref's own log: evs marks a CLOSURE's path versions, and a reader accepts an admin's push there only where the log shows a CLOSURE at that version whose content hash equals the version before it (§16.11's closure row; owner decision 636; ledger id QD-1100; the plan's RECORD-M10-05).
- **Why.** The owner accepted the draft's rule for an erasure's CLOSURE and left this check to the review phase: it is a reader-side check, with no format change if the cards read already exposes a push's kind.
- **Launch instead.** A reader accepts a directory admin's push at a `d/` or `r/` path only when its bytes are the very bytes its copy already accepted there, or else verify as the rightful writer's own Signed under every other rule, whose seq must rise (§16.11's closure row).
- **Lost.** Until the check lands, a reader that has accepted nothing at a path, a fresh device or one whose copy was reset, has no seq to hold a rewrite to: a directory admin that kept the bytes of a writer's earlier Signed file could push them as a CLOSURE, and such a reader would show them as the writer's, a card within the 4,096-position bound of its `at`, a repo file at whatever position its signer named, until the writer's next write or its repair replaces them.
- **Dark in code.** Nothing is built. The reader rule above is drafted and held by its tests.
- **Held.** The review phase's work on the directory's erasure. An admin-signed eraser card, option 2 of the question, is the one to design if the owner later wants moderation to keep a writer's other runs, or a revoked run gone before its daemon wakes.
- **To bring back.** evs marks the path versions a CLOSURE writes; the cards read exposes each push's kind; readers apply the check; and a test replays an earlier Signed card to a fresh reader and sees it refused.

<a id="mcp-v1"></a>
### §16's v1 set

*v1 (M6, M10). DESIGN.md: §16.18.*

- **Deferred.** §16.18's v1 rows. At M6: the team record and the team directory as the coordination log, mirrored on admins' indexers (owner decisions 102, 150, 171, 177); reach receipts; agent subkeys; filesystem events; model calls (owner decision 463); retention policies; the `audit` reader (owner decision 63); RECORD.md's verifiable log and client disclosure packets. At M10 (owner decisions 163, 169): the evs tools' versioning argument; `ur search`, `ur agents`, `search`, `search_agents` and `search_status`; run cards; the directory's cards and index; `evs_drop_preview` and the drop states; remote serving on indexers.
- **Why.** Team ships at M6 and format 2 with search at M10.
- **Launch instead.** v0 at M3: the in-daemon MCP server and `.ur`, R and W tools with restore, harness hooks, transcript tails and the redactor, the vault record, approvals and the use ledger; O tools with their components through M4-M9.
- **Lost.** Until M6: the team record and directory. Until M10: search and drops in the tools.
- **Dark in code.** Built in the same run on the `sidecar` branches.
- **Held.** Nothing.
- **To bring back.** Nothing to bring back: each ships when its milestone's gate passes (§23.6).

<a id="s17"></a>
## §17 IP addresses, subnet routing, and port forwarding

<a id="bridge-l3-delivery"></a>
### L3 delivery

*Later. DESIGN.md: §17.18.*

- **Deferred.** Delivering IP packets at layer 3 between sidecars, named in §17.18's Later row. It has no D- item, task or FS row.
- **Why.** DESIGN.md gives no reason beyond the Later row. D-BRIDGE-1 reuses connect's client-to-provider NAT path, so targets need no tun or root.
- **Launch instead.** The provider's NAT path: sender routing, a per-flow provider decision, one hop (§17.5, §17.6).
- **Lost.** What a routed path gives over a NAT one: the sender's own address at the destination, and protocols that do not cross NAT.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design for a routed path with a tun on both ends, and how §17.8's rules apply to it.

<a id="bridge-multi-hop-maps"></a>
### Multi-hop maps

*Later. DESIGN.md: §17.18.*

- **Deferred.** Port maps and routes that cross more than one sidecar, named in §17.18's Later row. It has no D- item, task or FS row.
- **Why.** DESIGN.md gives no reason beyond the Later row. D-BRIDGE-1 keeps the path to one hop.
- **Launch instead.** One hop. A provider never dials another host's block address for a flow it received (§17.6's rule 2).
- **Lost.** A destination behind a second sidecar is not reachable through the first.
- **Dark in code.** Nothing is built. The provider hook denies a block address not hosted on the device.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design for who authorizes each hop and how loops are refused.

<a id="bridge-ipv6-subnet-routes"></a>
### IPv6 subnet routes

*Later. DESIGN.md: §17.18, §23.4.*

- **Deferred.** Advertising and routing IPv6 subnets (§17.18; §23.4).
- **Why.** The overlay is IPv4 only: one IPv4 /16 per network and no IPv6 overlay (§17.4; owner decision 28).
- **Launch instead.** IPv4 subnet routes. Private names answer NODATA for AAAA (the plan's BRIDGE-M4-14).
- **Lost.** An IPv6-only subnet behind a sidecar cannot be reached.
- **Dark in code.** Nothing is built. The route statements are IPv4.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** An address plan for IPv6 in the overlay, new statement fields, and the conflict and HA rules of §17.7 for them.

<a id="bridge-v1"></a>
### §17's v1 set

*v1 (M6). DESIGN.md: §17.18.*

- **Deferred.** §17.18's v1 row: cross-network shares through C18, with ShareKeys, per-generation ShareSigners and the preflight; `ur tun` on macOS and Windows; P2P, built at M6 behind `EnablePeerP2p` and off until an owner call (owner decision 296).
- **Why.** Shares and the other platforms' tun belong to M6 (owner decision 86).
- **Launch instead.** v0 at M4, same network, Linux and WSL2 first; at M8, forwarding in every app's VPN component (owner decision 197).
- **Lost.** Until M6: sharing across networks, and `ur tun` on macOS and Windows.
- **Dark in code.** Built in the same run on the `sidecar` branches. P2P's switch has its own entry under §6.
- **Held.** Nothing.
- **To bring back.** Nothing to bring back: it ships when M6's gate passes (§23.6).

<a id="s18"></a>
## §18 SDK, apps, and extension integration

<a id="sdk-extension-worker"></a>
### The extension's own Worker

*Later. DESIGN.md: §5.17, §18.17, §22.17, §23.4.*

- **Deferred.** The browser extension running the sidecar itself as a web worker, with its streams (owner decision 26; R-CTX-5, R-ARCH-4; §5.17, §18.4, §18.8, §18.17, §22.17, §23.4). §22's rows for it wait with it.
- **Why.** Owner decision 26: HTTPS-only first, and connect streams follow C4. The extension's Worker also waits on §18.10's size spike and C17.
- **Launch instead.** The extension uses a desktop `ur daemon` over native messaging, `ur native-host`, where one exists; without one it is alarms-only. ur.io pages use the read-only page Worker.
- **Lost.** An extension with no desktop daemon beside it has no sidecar: no vault, no approvals of its own, and `PreviewRevokeDevice` and `RevokeDevice` answer `REVOKE_NOT_CAPABLE`.
- **Dark in code.** On js, `NewSidecarLocal` answers unsupported and `NewSidecarRemote` runs over a host-supplied `ur native-host` port (sdk/sidecar.go, sdk/sidecar_types_js.go). `ur native-host` relays no call that §5.8 signs only on confirmation.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** C4, and C17 if the spike asks for it; a Worker main within `sidecar.wasm`'s size gate; the rule that the Worker accepts only its own extension pages' ports; and §22's extension rows.

<a id="sdk-firefox-session-mode"></a>
### Firefox session mode

*Later. DESIGN.md: §18.17.*

- **Deferred.** Firefox session mode, named in §18.17's Later row. It has no D- item, task or FS row.
- **Why.** DESIGN.md gives no reason beyond the Later row. On Firefox the extension runs in an event page, and both it and its Worker unload when idle (§18.8).
- **Launch instead.** §18.4's feature table gives what the extension does on Firefox, with the mark "awake" for what needs the event page alive.
- **Lost.** DESIGN.md does not say.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A design that says what the mode is, with the extension's own Worker.

<a id="sdk-remote-search-requesters"></a>
### Browser Workers and ephemeral CLI hosts as remote-search requesters

*Later. DESIGN.md: §18.17.*

- **Deferred.** Asking a designated indexer to search from a browser Worker or an ephemeral CLI host (§5.4's requester methods; §18.13's Q-SDK-6; §18.17). Browsers also wait on C4.
- **Why.** Remote search's requester side is on app hosts only (owner decision 175). A browser tab's Worker carries no connect client.
- **Launch instead.** A browser tab downloads the index and searches locally, as a phone does when no indexer is online (owner decision 155).
- **Lost.** A browser tab or a short-lived CLI host pays the index download before it can search.
- **Dark in code.** Nothing is built. The requester methods exist for app hosts only (§5.4).
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** C4 for browsers, then the requester's Hello and policy on those hosts, with no keepalive (owner decision 609).

<a id="sdk-v1"></a>
### §18's v1 set

*v1 (M6, M10). DESIGN.md: §18.17.*

- **Deferred.** §18.17's v1 rows. At M6 (RS2): the team console on the page Worker, with the directory's read-only views; the `sdk.Sidecar` shell with `SignEdgeLogin`; the directory's seams. At M10 (owner decision 169): the search policy and targets, `SidecarSearch`, windows on app hosts and remote search's requester side; the page Worker's search; `Write`'s versioning argument, the drop calls and `History`'s states (owner decisions 173, 183).
- **Why.** Team ships at M6 and format 2 with search at M10.
- **Launch instead.** v0: CLI hosts through M1-M4, the ur.io/recurd page at M4 (RS1), app hosts at M8 (BS1).
- **Lost.** Until M6: the team console. Until M10: search and drops in the SDK.
- **Dark in code.** Built in the same run on the `sidecar` branches; the `sdk.Sidecar` shell lands dark at M6.
- **Held.** Nothing.
- **To bring back.** Nothing to bring back: each ships when its milestone's gate passes (§23.6).

<a id="s19"></a>
## §19 Server services: deployment, data stores, operations

<a id="ops-small-object-packing"></a>
### Packing small segments on the HDD tier

*Later, at its triggers. DESIGN.md: §19.18.*

- **Deferred.** Q-OPS-2's option (a): packing segments under 1 MiB and older than 7 days into larger objects on the HDD tier, never kind-5 segments, which stay deletable one by one (§19.14, §19.18).
- **Why.** The peer review closed Q-OPS-2 with (b) in v0 and (a) as a switch: packing does not reduce GETs, which are about 25,600 of year two's 32,000 drive operations a second, and it turns on only once HDD drive operations pass 50% of measured capacity, after §22.8's `hdd` row at M3.
- **Launch instead.** Q-OPS-2's (b): segments are not packed on the HDD tier. The page cache serves most GETs, and HDD sets per D-OPS-17 carry the rest.
- **Lost.** Nothing until the trigger. Past it, small objects use HDD drive operations that packing would save.
- **Dark in code.** Format 1 freezes what packing needs, so it needs no format change: content-id segment ids, the reserved `spidx/` family and its lookup order, and reserved locator kinds 3 and 4, never a physical address.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** §22.8's `hdd` row gives the measured capacity; monitor shows HDD drive operations past 50% of it; then the packer, `spidx/`'s writer and readers, and its FS row are built and the switch turns on.

<a id="ops-next-metadata-cluster"></a>
### The next metadata cluster

*Later, a tracked item at §19.9's triggers. DESIGN.md: §19.18, §22.17.*

- **Deferred.** A second metadata cluster, and later ones on new hosts (D-OPS-17; owner decisions 136, 145; §19.9, §19.18, §23.7). FS-63 and FS-119 run again before each new cluster takes repos (§22.17).
- **Why.** v0 has one cluster and one site for metadata (owner decision 94). The metadata tier grows only by whole clusters (owner decision 145), ordered when a trigger fires.
- **Launch instead.** One PM9A3 set of 8 drives with spares. §11.13's write budget refuses the heaviest network first when the set nears its limits.
- **Lost.** Nothing until a trigger. If the order comes late, the write budget refuses pushes, and a full cluster answers 507 CLUSTER_FULL (D-OPS-22).
- **Dark in code.** Placement is built: each repo is placed on a cluster at creation by a create-only `place/<repo_id>` object, so a second cluster needs no format change. monitor projects the triggers.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A trigger: 50% of raw capacity, 40% of inodes, 0.5 drive writes a day, or monitor's projection of one within the hardware's lead time. Then the hardware order, the cluster's bring-up, and FS-63 and FS-119 on it before it takes repos.

<a id="ops-segment-placement"></a>
### The segment placement and added HDD capacity

*Later, a tracked item at §19.9's hdd trigger. DESIGN.md: §11.22, §19.18, §23.4.*

- **Deferred.** A placement for segments that keeps §11.13's receipt check and moves upload load, not only new repos, to added HDD sets; and the added HDD capacity itself (owner decision 550; Q-OPS-11; Q-OPS-2's residual; D-OPS-17; QD-132; §11.22, §19.9, §19.18, §23.4, §23.7).
- **Why.** It is needed before year two's HDD load, not at launch. Owner decision 550 made it a tracked item with a lead time, so that undesigned work with no milestone still has a due date.
- **Launch instead.** One HDD cluster of 4 hosts (owner decision 94). Uploads are admitted up to 50% of its measured drive operations.
- **Lost.** Nothing until the trigger. Past it, uploads are refused at the admission line.
- **Dark in code.** Nothing of the placement is built. monitor's `hdd_trigger_lead_days` is 182, and the rota owns the page.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** Engineering writes the placement's design within 8 weeks of M3's exit, when the hdd run first gives an admitted throughput (Q-OPS-11's residual). The work starts at M3's exit and is due before the crossing that §19.9's hdd trigger projects, with a lead time of 26 weeks.

<a id="ops-second-site"></a>
### A second site or an off-site copy

*Later, decided from operating data. DESIGN.md: §19.18.*

- **Deferred.** A second site for the services and the file clusters, or an off-site copy of the file clusters (owner decisions 89 and 94; Q-OPS-7; §19.18).
- **Why.** The owner's words (owner decision 94): "v0 will have only one cluster and site for each metadata and storage, with 2 replicas in minio." Whether a second site comes in v1 or later is decided from operating data (owner decision 89).
- **Launch instead.** One site. The RPO and RTO targets cover drive and host failures only, and the file clusters have no off-site copy.
- **Lost.** A site loss loses server-held data on the file clusters. Recovery is from devices' local copies (§19.10), and a hold's kept objects are void (§21.9).
- **Dark in code.** Nothing is built. §7.9's site-loss resumption and §19.10's restore are the launch path for a lost site.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** Operating data on failures and growth, an owner decision, then a design for replication that keeps evs's single commit point.

<a id="ops-v1"></a>
### §19's v1 set

*v1 (M6, M10). DESIGN.md: §19.18.*

- **Deferred.** §19.18's v1 rows. At M6: migration group MG6, then `escrow_draw_order` on (§20.9); the team directory's load; 24/7 review. At M10 (owner decision 169): §19.11's `format2` gate with its purge and drop modes, each observe first and then on; the sweep and D-OPS-21's bounds; the search index's load in §19.9's projection (owner decision 174).
- **Why.** Team ships at M6 and format 2 at M10.
- **Launch instead.** v0: §19.11's rollout order, dark first; one metadata set and the HDD cluster; the sidecar dump with its restore and re-seed drills; infrastructure paging from M3 and business-hours abuse review.
- **Lost.** Until M6: Team billing's draw order and round-the-clock review. Until M10: format 2 in production.
- **Dark in code.** Built in the same run. MG6's migrations stay pending until M6's Gn-out, and the `format2` gate admits internal networks and design partners first.
- **Held.** Nothing.
- **To bring back.** Nothing to bring back: each ships when its milestone's gate passes (§23.6).

<a id="s20"></a>
## §20 Tiers, quotas, metering, and billing

<a id="quota-auto-recharge"></a>
### Auto-recharge of data packs

*Later. DESIGN.md: §20.16.*

- **Deferred.** Buying the next Community or Pro data pack automatically when one runs out, named in §20.16's Later row. It has no D- item, task or FS row.
- **Why.** DESIGN.md gives no reason beyond the Later row. Team needs none, since it is post-paid.
- **Launch instead.** A person buys a data pack by hand. When a balance runs out, the limit's refusal says so (§20.7).
- **Lost.** A Community or Pro network that runs out of transfer is refused until someone buys a pack.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A stored payment method with consent to charge it, a cap, and the purchase path's idempotency under §20.6's draw order.

<a id="quota-invoicing-above-25-seats"></a>
### Invoicing above 25 seats

*Later. DESIGN.md: §20.16.*

- **Deferred.** Billing a Team by invoice above about 25 seats (R-QUOTA-6; §20.16).
- **Why.** DESIGN.md gives no reason beyond the Later row.
- **Launch instead.** Team pays by card through checkout. Invoiced teams use market `manual` (§20.5), and DESIGN.md gives them no self-serve path.
- **Lost.** A larger team cannot start or change an invoiced plan by itself.
- **Dark in code.** The `manual` market is the seam.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** Invoices, terms and dunning in the billing provider, and the seat meter's report to it.

<a id="quota-financial-claim-shares"></a>
### Retuning taskworker's financial claim shares

*Later, once service debits carry production volume. DESIGN.md: §20.16.*

- **Deferred.** A claim share for `FlushServiceDebits`, and with it a retuning of production's financial shares (owner decision 521's option 2; QD-943; §20.6's flush row).
- **Why.** The four existing claim shares at period 8 already spend the half of ordinary claim turns the scheduler allows, and a fifth share at any period would panic every taskworker at construction. Service debits ship dark at M2, so there is no volume to measure yet.
- **Launch instead.** `FlushServiceDebits` takes no claim share. Its chains run on the ordinary queue and their function's indexed lane.
- **Lost.** Behind a totals backlog a flush may wait about a minute per claim, and balances read higher than they are for that long. It delays only the Postgres debit and the token release, never a refusal.
- **Dark in code.** Nothing is switched off. The shares are in server/taskworker/claim_admission.go.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** Service debits carry production volume, M5's tls leases at the earliest. Then, from a measurement, the owner of those tunings sets `FlushTransferDebits`, `AdvancePayment` and `FlushServiceDebits` at period 12 each and the totals lane and its drain at 8.

<a id="quota-v1"></a>
### §20's v1 set

*v1 (M6, M10). DESIGN.md: §20.16.*

- **Deferred.** §20.16's v1 row. Team at M6: the `team` tier and its prices, seats, checkout, meters, credit line, downgrade jobs and share escrow, with D-QUOTA-9's comparator built dark in M4; the directory's request limits (D-QUOTA-11). Format 2 at M10 (owner decision 169): the search index counting as storage, versionless content's counting and freeing, the drop's rates and freed-byte reports (D-QUOTA-12), and remote search's relayed bytes.
- **Why.** Team ships at M6 and format 2 at M10.
- **Launch instead.** v0: free and pro tiers with their `sidecar:` blocks, counters and refusals at M1; the debit path and leases at M2; edge lease spending at M5, M7 and M9.
- **Lost.** Until M6: the Team tier. Until M10: format 2's accounting.
- **Dark in code.** Built in the same run. The escrow comparator's index is pending in MG6 until M6's Gn-out, and a drop frees nothing until §19.11's `drop` gate turns on (D-PHASE-12).
- **Held.** Nothing.
- **To bring back.** Nothing to bring back: each ships when its milestone's gate passes (§23.6). M6's entry runs §20.9's benchmark and FS-46.

<a id="s21"></a>
## §21 Abuse, safety, and legal process

<a id="abuse-preservation-holds"></a>
### Preservation holds, turned on

*Built at M5, off until counsel confirms. DESIGN.md: §21.18.*

- **Deferred.** Placing a preservation hold (§21.9; owner decisions 133, 525, 526, 528, 529; §23.7).
- **Why.** Owner decision 133's condition: counsel confirms it, and each hold kind's applicability (`preserve_2703f`, `report_2258a`), before any hold is placed.
- **Launch instead.** Holds are built and tested, and `holds_enabled` is false, so placement is refused.
- **Lost.** Until counsel confirms, a preservation request cannot be met by placing a hold.
- **Dark in code.** abuse.yml's `holds_enabled`, false (server/abuse_config.go; server/controller/abuse_hold_controller.go refuses placement).
- **Held.** Nothing in the build. §23.7 tracks counsel's confirmation.
- **To bring back.** Counsel's confirmation of owner decision 133's condition and of each hold kind; then `holds_enabled` is set true in each environment's abuse.yml.

<a id="abuse-v1"></a>
### §21's v1 set

*v1 (M6, M10). DESIGN.md: §21.18.*

- **Deferred.** §21.18's v1 items: 24/7 review and tightening the team directory's request limits at M6 (§21.7); at M10 (owner decision 169), holds deferring a drop's deletions (owner decision 184).
- **Why.** Team ships at M6 and drops at M10.
- **Launch instead.** v0 at M5, before any public name: §21.6 to §21.10 with the report host, the DMCA agent and business-hours review, with notices on §19.8's rota (owner decisions 134, 143).
- **Lost.** Until M6: review outside business hours, other than the notices the rota carries.
- **Dark in code.** Built in the same run on the `sidecar` branches.
- **Held.** Nothing.
- **To bring back.** Nothing to bring back: each ships when its milestone's gate passes (§23.6).

<a id="s22"></a>
## §22 Testing and verification

<a id="test-synthetic-main-network"></a>
### The synthetic main network

*Later. DESIGN.md: §22.17.*

- **Deferred.** A synthetic network on main that repeats scenarios S2 and S5 to S7 every hour (D-TEST-5; QD-594; §22.17).
- **Why.** D-TEST-5 puts it beyond M0-M10. No task builds it (QD-594).
- **Launch instead.** Every scenario runs §22.7's harness and guard at its gate, on T1 to T4.
- **Lost.** No hourly end-to-end probe of production. A break that the monitors' own signals miss shows first to a user.
- **Dark in code.** Nothing is built.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** A network on main set aside for it, the scenarios packaged to run against production under §2.8's rules, and alert classes for their failures.

<a id="test-v1"></a>
### §22's v1 set

*v1 (M6, M10). DESIGN.md: §22.17.*

- **Deferred.** §22.17's v1 rows. At M6: S3b, S4b, the OIDC, JIT, SCIM and custom-domain rows, the seat cases, FS-30's audit reader, S13, FI-25, FI-26 and the M6 cases of FS-84 to FS-88 and FS-97 to FS-101. At M10 (owner decision 169): S11, S12, FI-16 to FI-24, FI-27, FS-64 to FS-81, FS-83, FS-89 to FS-96, FS-107 to FS-112, FS-114's purge and drop cases and FS-125; the index vectors on every leg; git-lfs conformance; both models and `EvsCommit.tla`'s drop extension.
- **Why.** Each test runs at its component's milestone (§23.6's gate map).
- **Launch instead.** v0's rows: T1 to T4, the M2 storage benchmark with D-TEST-11's gate, and each FS at its gate through M9.
- **Lost.** Nothing: a test waits with what it tests.
- **Dark in code.** Built in the same run; the fault catalog holds each row to its gate.
- **Held.** Nothing here. TEST-M6-03 is held with the prefix write rules, under §8's entry.
- **To bring back.** Nothing to bring back: each runs at its milestone's gate (§23.6).

<a id="s23"></a>
## §23 Phasing, milestones, and rollout

<a id="phase-rs3-assurance-stage"></a>
### RS3, recURd's assurance stage

*Later. DESIGN.md: §20.16, §23.4.*

- **Deferred.** RS3, the third of recURd's stages, "inbox and assurance", released whole once its assurance items land (R-PHASE-4; §20.16, §23.4, §23.16). Its items are a team's own legal holds, compliance mappings, and self-hosted and air-gapped installs; each has its own entry.
- **Why.** R-PHASE-4: the three stages ship whole, in order. RS3's assurance items are outside M0-M10.
- **Launch instead.** RS1 at M4 and RS2 at M6, each released once its last item lands, and BS1, the burner launch, at M8.
- **Lost.** RS3 is not released as a stage, since a stage ships whole.
- **Dark in code.** Nothing is built. The gate tool's `stages.yml` lists RS1, RS2 and BS1 and has no RS3 row (server/local/sidecar-gate).
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** Each assurance item is designed and built; then RS3 gets its row in `stages.yml` and its release review.

<a id="phase-compliance-mappings"></a>
### Compliance mappings

*Later, with RS3. DESIGN.md: §23.4.*

- **Deferred.** Mapping the product's controls to compliance frameworks, named in §23.4's Later paragraph. It has no D- item, task or FS row.
- **Why.** It is an RS3 assurance item. DESIGN.md gives no further reason.
- **Launch instead.** The trust documents of §21.11 and §2.8's published list say what servers see; no framework mapping is claimed.
- **Lost.** A buyer who needs a mapping to a named framework does not get one.
- **Dark in code.** Nothing: a mapping is a document.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** The owner names the frameworks; the mapping is written against the built system; RS3's review reads it.

<a id="phase-self-hosted-installs"></a>
### Self-hosted and air-gapped installs

*Later, with RS3. DESIGN.md: §23.4.*

- **Deferred.** Running the server services on a customer's own infrastructure, air-gapped included (owner decision 48; Q-CTX-1; §23.4).
- **Why.** Owner decision 48: self-hosting comes at the later "assured" stage and is kept possible from v0. There is no self-hosted bundle in v0.
- **Launch instead.** URnetwork runs every server service.
- **Lost.** A customer who must run the services itself cannot use the product.
- **Dark in code.** The seam is built: engines reach URnetwork-only infrastructure (Route 53, warp, shared Postgres, connect relays) only through operator-core's interfaces, whose instances an `Env` creates (D-REPO-3; owner decision 251), and `make check`'s layering rules hold it.
- **Held.** Nothing: no task or track waits on it.
- **To bring back.** An `Env` over a customer's own stores and DNS, a bundle with its install and upgrade path, an answer for connect relays in an air gap, and the release's signing story for a build URnetwork does not run.
