# Design amendments

Every design decision made since DESIGN.md was last rebuilt and not yet folded into it, ordered by the DESIGN.md section it amends. The decisions were taken in the run's question ledger (`.stack/decisions/LEDGER.json`, ids QD-001 to QD-651), which lives outside git; this file is their durable copy in the sidecar repo.

**Precedence.** Where an item here and DESIGN.md differ, the item governs until it is folded. A complete section of DESIGN-DETAILS.md governs the tasks it names, and where an owner decision below answers one of its questions, the decision governs. Decided items are the owner's; proposed items are the agents' readings and fills, which work builds on until the owner says otherwise.

**Folding.** Only a design-records track edits `design/source/` and rebuilds DESIGN.md with `design/source/build.sh`. Each design-records track takes one DESIGN.md section, applies its items below (and the matching "Proposed DESIGN.md text" of DESIGN-DETAILS.md), and in the same commit deletes those items from this file. When this file holds no items it is deleted. Owner decisions that change behavior go into `design/source/owner/DECISIONS.md` as numbered owner decisions, after decision 197, as decision 197 was.

Holds 252 decided items and 278 proposed ones, generated from the ledger on 2026-11-10. QD-597 (owner decision 197) is already folded.

## Index

| DESIGN.md section | Decided | Proposed |
|---|---|---|
| [§2 Trust model and threat model](#s2) | 3 | 0 |
| [§3 Architecture overview and end-to-end flows](#s3) | 1 | 0 |
| [§4 Repositories, code placement, branches, and build](#s4) | 15 | 21 |
| [§5 The Sidecar core](#s5) | 19 | 28 |
| [§6 The sidecar subprotocol](#s6) | 7 | 17 |
| [§7 Networks, teams, members, enrollment, and SSO](#s7) | 25 | 5 |
| [§8 Access control](#s8) | 14 | 13 |
| [§9 Abstract socket listeners and the scheduler](#s9) | 5 | 2 |
| [§10 Group keys for evs: MLS and the GKM service](#s10) | 23 | 15 |
| [§11 Encrypted versioned storage](#s11) | 25 | 37 |
| [§12 DNS](#s12) | 7 | 0 |
| [§13 The TLS edge and certificates](#s13) | 3 | 13 |
| [§14 The SMTP edge](#s14) | 8 | 13 |
| [§15 The local email server, inbound mail, and burner email](#s15) | 11 | 19 |
| [§16 The local MCP server and record primitives](#s16) | 28 | 21 |
| [§19 Server services](#s19) | 20 | 21 |
| [§20 Tiers, quotas, metering, and billing](#s20) | 7 | 18 |
| [§21 Abuse, safety, and legal process](#s21) | 17 | 17 |
| [§22 Testing and verification](#s22) | 7 | 15 |
| [§23 Phasing, milestones, and rollout](#s23) | 3 | 3 |
| [No section named](#s0) | 4 | 0 |

## DESIGN-DETAILS.md sections to fold

Sections 2, 4, 5, 6, 8 and 9 of DESIGN-DETAILS.md are complete; each ends with its proposed DESIGN.md text. Their owner questions were answered on 2026-11-10 (QD-598 to QD-629, below under the sections they amend). Three answers differ from a section's recommendation and the design agent amends the section before it is folded: QD-604 (section 8, imports make helper refs), QD-621 (section 4, an overdue narrowing statement keeps the last state and alarms) and the model and wording fixes of QD-628, QD-632, QD-633, QD-642 and QD-644. Sections 1, 3, 7, 10, 11, 12 and 13 are still being written.

Sections 8 and 9's owner answers are folded as owner decisions (2026-11-10): section 9's QD-607 to QD-610, QD-612, QD-632 and QD-633 as 227-233, with QD-613 (section 6's key prefixes) as 234 and QD-640 as 235, and section 8's QD-598 to QD-606 as 236-244, each stated in §11 where it binds. Their proposed DESIGN.md text (8.8, 9.8) waits for the design agent's amendments above, and is folded only with them.

Section 2.8 is folded (2026-11-10): where QD-623 (owner decision 203) needed it with §2's and §3's items, and the rest with §11's, as owner decisions 225 (QD-624) and 226 (QD-625). One part waits: FS-59's checks column, FI-1,6 for FI-6, which sidecartest/fault/catalog.yml must take in the same change, since the fault catalog's test holds each FS row's checks to that file and a design-records track edits no test data; FS-59 keeps FI-6 meanwhile. Of the other sections' §2.8 parts, those their items name are folded: 4.8's (QD-622), 5.8's two settings (QD-629), 6.8's gkm-1 (QD-614), 9.8's evs-11 places (QD-611) and 13.8's (QD-657). Still to fold, with their sections: 5.8's other api-7 words (tail verdicts, open proposals, the applied-id ring, confirmations), which ProjectionHeader.tail_verdicts and ProjectionRows.proposals and ring already carry in protocol/bridge/auth.proto; 6.8's gkm-5 pointers (QD-618, under §10); 8.8's evs-4 words; and 9.8's evs-11 ttl.

<a id="s2"></a>
## §2 Trust model and threat model

### QD-012: How sidecar.ur.io is served, given that Cloudflare terminates ur.io
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §18, §19.*

Serve `sidecar.ur.io` direct: it joins warpctl's `domains` and mmm's `expose_aliases` as W10 does, under a W5 certificate at the lb, as an unproxied record, and `warpctl dns` refuses it proxied (a new name starts unproxied today, warp/warpctl/dns_cloudflare.go:252). Those values live in vault, so that edit is external. Add an ext row and an EX7 clause to §2.8 saying Cloudflare terminates https://ur.io: it sees page requests and can alter page script, so views while it runs, never the key origin's code, key or token.

Changes: §2.8 EX7; §2.8 ext rows; §2.4 TB1; §18.8; §19.5 W10.

Questions: `plan-SDK-small-readings.md#3`.

Not folded (2026-11-10): the ext row for Cloudflare, since a new §2.8 row needs its `planned` line in testdata/metadata/fields.yml in the same commit, which a design-records track does not edit (question `dr-s2-s3-new-metadata-rows.md`); the rest is folded as owner decision 211 (§2.8 EX7, §2.4 TB1, §2.10, §18.8, §19.5's W10).

### QD-023: Which key signs apt and yum metadata, and where do those repositories live?
*Decided by the owner: owner 2026-11-06. Also amends §4.*

the file's option 3: drop apt and yum from v1, and keep .deb and .rpm as direct downloads through install.sh's verified path. No GPG key and no repository host. §4.18 loses that item, and `apt upgrade` needs a Q- item. This replaces Proposed. (The recommendation it replaces: A second offline key, a GPG key held and used in the same two-person ceremony as the SSH key: `InRelease` and rpm signatures are made at promotion, and the trees publish under `https://ur.io/recurd/apt/` and `https://ur.io/recurd/yum/` through mmm. If the owner would rather cut scope, drop apt and yum from v1 and keep `.deb` and `.rpm` as direct downloads, with a Q- item.)

Changes: §2.6; §4.10; §4.18.

Questions: `plan-REPO-v1-channels.md`.

Not folded (2026-11-10): the Q- item for `apt upgrade` that the owner asked for, since a new §4 id needs its evidence line in check/repo_matrix_test.go's repoMatrix in the same commit (TestEveryRepoIdHasEvidence), which a design-records track does not edit (question `dr-s2-s3-new-metadata-rows.md`); the rest is folded as owner decision 213 (§2.6, §4.10, §4.18).

### QD-030: Who holds the abuse and legal-request mailboxes, and what can that provider read?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §21, §19.*

Both mailboxes sit at one provider outside URnetwork's Postgres and clusters, the owner naming it. Every record is sealed to a vault-held HPKE key before it leaves the process, so the provider and SES see sender, time and size only; §19.10's restore opens them with that key. api-14 names both mailboxes' copies: action records "kept as api-14's actions", hold records until the hold's `expire_time`. A new ext row lists the provider with what it sees: sealed records, their time and size.

Changes: §2.8 api-14; §2.8 ext rows; §21.10; §21.16; §19.10.

Questions: `plan-ABUSE-metadata-rows.md#4`.

Not folded (2026-11-10): the new ext row for the mailboxes' provider, since a new §2.8 row needs its `planned` line in testdata/metadata/fields.yml in the same commit, which a design-records track does not edit (question `dr-s2-s3-new-metadata-rows.md`); the rest is folded as owner decision 208 (§2.8 api-14, §19.10, §21.10, §21.16).

<a id="s3"></a>
## §3 Architecture overview and end-to-end flows

### QD-242: Whether a checkpointer's HTTPS POST to a customer's witness may exist, as a new carrier under D-ARCH-2
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

Rule it no URnetwork carrier, in one sentence in §3: a checkpointer's own outbound HTTPS call to a witness a log admin named in a signed, /dev/tty-confirmed `log_settings`. It carries a signed note and a consistency proof, never an entry, no agent can set the host, and §2.8 stands because no URnetwork server takes part. §3.5's map names it as outside the six planes, and RECORD.md section 10.2's step 6 turns on.

Changes: D-ARCH-2; §3.5 planes; RECORD.md section 10.2; Q-RECORD-8.

Questions: `record-md-witness-carrier.md`.

Not folded (2026-11-10): RECORD.md section 10.2's step 6 and Q-RECORD-8, which live in RECORD.md, outside design/source/ and so outside a design-records track's files; the DESIGN.md part is folded as owner decision 214 (D-ARCH-2, §3.5).

<a id="s4"></a>
## §4 Repositories, code placement, branches, and build

### QD-002: Unlicensed MLS test vectors sit in the sidecar history
*Decided by the owner: owner 2026-11-06. Also amends §10.*

the file's option 2: commit the mlswg vector files in testdata/mls/mlswg/ as §4.4 and §10.4 say. This replaces Proposed and Interim: the files stay in git, and no history rewrite is needed. (The recommendation it replaces: [mls-base-mlswg-vector-license#1] Recommended: publish no mlswg bytes until a grant exists, and ask for one. testdata/mls/mlswg/ keeps only SOURCE and SHA256SUMS in git. `make mls-vectors` runs go mod download -json github.com/mlswg/mls-implementations@v0.0.0-20261007145543-2034fe72e0c8, copies test-vectors/*.json into that directory, which is gitignored, and checks SHA256SUMS. go:embed still covers every leg, wasm included, and a missing file fails a test, never skips it. The module is never required or linked, so §4.7 and dependencies.yml need no exception. The owner sends one email asking the mlswg to add a license; a grant turns this into one commit of the 16 files. The files are already in local `sidecar` history, so this answer also needs the owner's exception to the rule against rewriting landed history, taken before any push. [mls-base-mlswg-vector-license#2] Recommended: keep the four vectors in testdata/mls/xwing/ with attribution: SOURCE names each draft, its authors and the IETF Trust and cites BCP 78. If the owner or counsel objects, use the KEM 0x647a entries of GOROOT's crypto/hpke/testdata/hpke-pq.json, which carry Go's BSD license and may be copied with its notice.)

Changes: §4.4 testdata row; §10.4 conformance; KEYS-M2-10's vector source; testdata/mls/xwing/SOURCE.

Questions: `mls-base-mlswg-vector-license.md#1`, `mls-base-mlswg-vector-license.md#2`, `plan-KEYS-mlswg-license.md#1`.

### QD-017: How does an offline, two-person signature fit a release pipeline that runs unattended and almost daily?
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Promote, rather than sign every build. Every release builds `ur`'s artifacts and an unsigned `SHA256SUMS` as ordinary assets, and run.sh waits for no one. When both holders pick a release they sign its sums offline, and a commit on mmm publishes `SHA256SUMS`, `SHA256SUMS.sig` and `latest.json` under `https://ur.io/recurd/ur/`. `latest.json` is listed in the signed sums, and `ur-promote.zsh` never moves it backward. `install.sh` reads that pointer, verifies, and fetches artifacts from the GitHub release. No private key touches the build host, the repo or vault. Residual to state in §4.10: a fresh install cannot tell an older signed pair from the newest, so ur.io could roll a new install back to an older signed release.

Changes: §4.10; D-REPO-7.

Questions: `plan-REPO-release-signature-flow.md`.

### QD-024: cli/UI.md is on no path this run can read
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Put a copy at sidecar/design/UI.md. Its spellings then replace #2, #4, #5 and #6 below, each a one-line rename behind registerUrCommand.

Changes: §4.11; HANDOFF section 2.

Questions: `plan-CORE-cli-ui-missing.md#1`.

### QD-113: A Required session opens inbound frames while its signed-identity gate is pending or has rejected the key
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §5, §17.*

Add a default-off `EncryptionSettings.GateReceiveOnSignedIdentity`, in its own change (D-REPO-5). On, `unwrapFrame` opens nothing for a session whose `keyHistoryState` is pending, rejected or store-unavailable and returns a distinct gated result. `Client.run` drops that frame with no ack and counts it, and must not call `NotifyUndecryptableWrap`, whose nack would drive a re-handshake; gating inside `decryptCiphers` alone would trigger exactly that. A pending peer's frames recover by the sender's resend once the gate clears. Sidecar clients and §17.5's bridge window clients set it on. Other Required clients stay off until their own production rollout. Reword `cipherWithLock`'s comment so it claims the receive side only with the setting on.

Changes: §4.6 C15; connect/DESIGNNOTES3.md §5.4.

Questions: `connect-m1-required-receive-gate.md`.

### QD-123: Where proving keys and transcripts live, and whether a desktop carries gigabytes of them
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §14.*

Option 1, after cutting shapes. Keys and transcripts download on first send from a public path on ur.io, pinned by hash in the release; the host verifies the transcript once per release (SPEC.md 10.2) and caches. No token and no account on the fetch. A new §2.8 row says the host sees the fetching IP, which marks a prover host. Reduce the 20 shapes to what M7's census justifies before the first production setup.

Changes: §4.10; §2.8 (new row); §14.5; smtpproof/SPEC.md 10.3.

Questions: `smtpproof-start-key-distribution.md`.

### QD-128: Whether server's competition graph and sn's release gates take sidecar as a repository before the first merge to main
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Recommended: add `sidecar` to both lists in one change landing with M0's Gn-out, before server and sn merge to `main`: an eleventh competition repository with an additive migration and rebuilt evaluator images, and a fourteenth release repository with a new `sidecar_go_source_hash`.

Changes: §4.7 Consumers; §4.8.

Questions: `wire-consumers-closed-source-graphs.md`.

### QD-131: Which commits does a Gn-out merge take once `sidecar` has run past that milestone?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §23.*

Recommend option 1: record each gate's pinned commit set when its local checks are reported, and at an approved Gn-out merge that set, never the tip, in §4.8's order; a later milestone's merge brings the rest. A group's migration registration (D-OPS-6) is the one commit on top of the set. §4.8 and §23.9 gain a sentence saying so.

Changes: §4.8; §23.9.

Questions: `design-records-gn-out-merge-commits.md`.

### QD-145: `strict_chain` claims a customer-signed chain that connect's DoH path cannot show
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §15, §23.*

Option 1, with the timing fixed. New connect change C20: `DohCache.ForwardDnssec(ctx, qType, domain)` sets EDNS0 DO on `Forward`'s query and returns the raw response; generic, additive, off by default, tested in connect and merged to connect `main` first (D-REPO-5). The device fetches MX, TLSA, DS and DNSKEY with RRSIGs and validates to its embedded root anchors. `strict_chain` is true only when that validation passes for every MX host of every recipient domain and the host's TLSA, with this key, in zones outside `<root>` and bringyour.com. SMTP-M9-05's wire parser and `SmtpDnssecChain.Validate` move to M7, because FS-33 gates M7-out and that task is M9's. ext-3's row gains the DS and DNSKEY lookups.

Changes: §4.6 (new C20); §2.8 ext-3; §15.5; §23.4 (validator moves M9 to M7).

Questions: `plan-MAIL-dnssec-evidence.md`.

### QD-193: Patched mail libraries have no home
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §15, §22.*

[plan-MAIL-go-smtp-fork] The in-tree fork of option 1, with one correction. `sidecar/third_party/go-smtp` keeps module path github.com/emersion/go-smtp and carries a URNETWORK.md naming the upstream tag and the patch, as server/third_party/pgx does. Replace lines: root `./third_party/go-smtp`; cli, smtpproof and mlsinterop `../third_party/go-smtp`; server, sn and the four sdk modules `../sidecar/third_party/go-smtp`. §4.7's list and `make check`'s hygiene row gain them. The correction: §4.9's and §22.4's release fixture builds the root at the tag with no replaces (REPO-M0-02), which links upstream go-smtp, so the root may name no fork-only symbol. The fork keeps D-MAIL-3's `ServeConn(conn, ServeConnOptions{AfterStartTls: true})` and adds `ServeTlsConn(conn *tls.Conn) error` over it, and `mail_smtp_serve.go` reaches that only through a local interface assertion on `*smtp.Server`. Against upstream's server the assertion fails and `mailSmtpServe` refuses, closed. If upstream takes the patch, delete the replaces and the assertion. Upstreaming stays an external action. [plan-MAIL-mox-subset] Option 1. `sidecar/third_party/mox` holds only the packages `dkim`, `dmarc` and `spf` need, with `mlog`'s three counters removed, a URNETWORK.md and both of mox's license files, behind the same replace lines as plan-MAIL-go-smtp-fork. `dependencies.yml` gains github.com/mjl-/mox as `MIT AND MPL-2.0` and github.com/mjl-/adns, client leg. No interface seam is needed: upstream's API is a superset, so the no-replace release fixture still builds, and `make check`'s legs run with the replace, so prometheus stays out of every leg. `mailAuthVerifiers` stays the one seam.

Changes: §4.7 replaces and hygiene; D-REPO-1; D-REPO-6; §15.5 Library; §4.7 replaces; dependencies.yml.

Questions: `plan-MAIL-go-smtp-fork.md`, `plan-MAIL-mox-subset.md`.

### QD-201: D-REPO-7's "no single origin may ship a client" does not hold for `install.sh`
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

D-REPO-7 and §4.10 say what holds: GitHub alone cannot ship a client, but ur.io serves both the script and its pin, so ur.io alone can, to a new script install. EX7 names the case. `install.sh` prints the key's fingerprint and the repository path that publishes it, so a careful user can compare, and nothing more is built. Notarization and Authenticode remain second checks on the macOS and Windows artifacts.

Changes: D-REPO-7; §4.10; §2.8 EX7.

Questions: `plan-REPO-small-readings.md#11`.

### QD-207: Should KEYS-M2-10 still build the mlswg interop client?
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

No. Remove "and the mlswg interop client" from §4.4's mlsinterop/ row and from mlsinterop/doc.go, and the interop-client step from KEYS-M2-10. mlsinterop/ takes no code from the mlswg module and no grpc dependency.

Changes: §4.4 mlsinterop row; mlsinterop/doc.go.

Questions: `plan-KEYS-mlswg-license.md#2`.

### QD-238: Where does the minio fork sit in the merge order, and which of its branches plays `main`?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §23.*

Recommend option 1: minio joins the warp/config/vault/xops/mmm group in §4.8's order and the branch policy, and its `master` plays `main`. Its weekly merge in is a no-op while upstream stays archived. In every option xops pins a commit of the fork in place of playbook-minio-clusters.yml's `minio_commit`, and that commit is on the public fork before a host runs it, as owner decision 195 keeps the AGPL source in one public place.

Changes: branch policy; §4.8; §23.9.

Questions: `design-records-minio-merge-rules.md`.

### QD-240: Whether tlshacks's MIT-plus-advertising-clause licence may stay on every connect leg
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Recommended: add X11 to §4.7's allowed list and to check's allowedLicenses, defined as MIT's text plus only this no-advertising clause, so licensePhrases pins both and refusedLicensePhrases lets that one id through; remove the module's exception. dependencies.yml keeps `X11`, the closest SPDX id.

Changes: §4.7; check/settings_test.go; check/deps_test.go.

Questions: `make-check-tlshacks-x11.md`.

### QD-246: How the keyless device role parses team hints, when Envelope and PushHint live in protocol
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §6, §22, §18.*

Move Envelope and Chunk (from envelope.proto) and PushReset, TopicVersion and PushHint (from push.proto) to a new protocol/bridge/push.proto; PollResponse stays in protocol/push.proto and imports them. Names and numbers do not change, so wire bytes do not, and the Go types become bridge.*. device/ keeps PUSH_RESET 0x0101 and PUSH_HINT 0x0102 as local constants, since MessageType stays in protocol/types.proto, with a test pinning them to it. Edit §4.4, §6.5, §6.8, §6.11's file list and §22.5's descriptor list, which gains protocol/bridge/push.proto. The move and the fence edit land together.

Changes: §4.4; §6.5; §6.8; §6.11; §22.5; §18.6.

Questions: `plan-PROTO-device-role-push-types.md`.

### QD-282: §4.7 names too few consumers
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

§4.7's Consumers line becomes: server, sn, build/all/acceptance and four sdk modules add the require and replace; server and sn also add `../sidecar/smtpproof`. sdk's `license.yml` is regenerated in the same change. HANDOFF's "sn repeats server's sidecar replace" follows.

Changes: §4.7; D-REPO-6.

Questions: `plan-REPO-small-readings.md#2`.

### QD-284: Which routes C11 owes at M1, given that its row names only §7, §8 and §11
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §7, §8, §11, §20.*

C11's M1 is when the spec lands, not when each route is served. connect-m1 keeps its 32 operations, marked `x-status: planned` and `x-internal: true`. Every other new route enters connect/api/bringyour.yml in the change of the task that first serves it, and that task lifts `planned`: CORE-M1-06 for `POST /sidecar/bind` and `GET /sidecar/identity/<sidecar_id>`, PROTO-M1-10 for the sync routes and poll, TEAM-M1-10 for `POST /sidecar/close`, KEYS-M2-01 for `/gkm/*`, the QUOTA tasks for §20.14's routes, each M6 Team task for its §7.17 route, and TEAM-M1-02, -03, -04 and -06 for field changes to served routes, since `TestSpecConformance` is SPEC ⊆ IMPL. EVS1-M2-21 teaches `TestSpecRoutesImplemented` and check-routes.sh to skip paths with their own `servers:` entry. `POST /evs/v1/repos/<id>/activate` follows plan-EVS1-repo-activate-route. design-records changes §4.6's C11 row to read `M1, then with each route's own task`.

Changes: §4.6 C11 row.

Questions: `connect-m1-c11-route-scope.md`.

### QD-304: "No replaces" in the fixture
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The fixture strips every replace and proves module paths, nothing about the forks. `ur` as run.sh builds it keeps `go_mod_edit_gvisor`'s pin and the rebased sctp replace, and REPO-M1-01 proves that with `go version -m`.

Questions: `plan-REPO-small-readings.md#3`.

### QD-305: The consumer wiring and the release step
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The wiring owns the go.mod requires and replaces, the lock entry, the service compile test and the `sidecar` submodule. REPO-M0-01 and REPO-M0-02 own run.sh and the fixture. If the wiring lands either first, the task shrinks to its tests.

Questions: `plan-REPO-small-readings.md#1`.

### QD-326: The version string
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The Version sed writes `${WARP_VERSION}`, as sdk's does, so `ur --version` prints the `+` form; artifact names and tags use `${EXTERNAL_WARP_VERSION}`. sidecar.go's comment showing `$WARP_VERSION-$WARP_VERSION_CODE` is corrected.

Questions: `plan-REPO-small-readings.md#6`.

### QD-336: Engine as three shapes
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Keep Engine (Ready, Drain, Close), HttpEngine (adds Handler() http.Handler) and StreamEngine (adds Serve(net.Listener) error). Each engine package states its shape with var _ sidecar.HttpEngine = (*EvsEngine)(nil), and sidecarhost.RunOptions takes the shape it serves rather than asking by type assertion. smtpedge is an Engine alone.

Changes: §4.5.

Questions: `core-types-engine-shape.md`.

### QD-345: App groups
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`ur` claims both `6BGU69Q742.group.network.ur` and `6BGU69Q742.group.com.bringyour.urnetwork`, or a direct-download app cannot reach the daemon's app-group socket.

Questions: `plan-REPO-small-readings.md#8`.

### QD-348: Documents and the module zip
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`go_mod_fork` gets `design/`, `research_notes/` and DESIGN.md as arguments, so they stay beside the module on the release branch, as server's `connect/sim-latency/baseline` does. `LICENSE`, `NOTICE` and `README.md` move with the module.

Questions: `plan-REPO-small-readings.md#5`.

### QD-358: An engine package at M0
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The fixture takes the first `<svc>service` it finds, and until one lands it adds `pushservice/doc.go` to its copy and logs that it did.

Questions: `plan-REPO-small-readings.md#4`.

### QD-373: T1 "on all §4.7 legs"
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Every leg compiles, and tests run on each leg this host can run. A leg it cannot run reports `not run`, which a gate lists as open and never as a pass.

Questions: `plan-TEST-small-readings.md#7`.

### QD-381: Windows
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The zip holds `ur.exe`, a copied `git-remote-ur.exe`, `LICENSE` and a README naming the folder and the PATH step. No `wintun.dll` until plan-BRIDGE-windows-tun-driver is answered. Unlike windows/app/build.ps1, this step fails when no signing thumbprint is set.

Questions: `plan-REPO-small-readings.md#12`.

### QD-385: C19's row drops "acked and unacked" from counted bytes
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §6.*

§6.10 (06-PROTO.md:453-454) governs: T is the client's counted bytes, acked and unacked. connect's C19 builds to that. Change C19's row (now 04-REPO.md:145) to "counted bytes, acked and unacked".

Changes: §4.6 C19.

Questions: `g0-density-text-alignments.md#4`.

### QD-386: Whether P2pPeerSourceOnly accepts a multihop stream's far end
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §11.*

Keep the strict rule. `ClientSettings.P2pPeerSourceOnly` holds a P2P carrier to its adjacent peer, so an opted-in client must not be the endpoint of a multihop stream, and SUBPROTOCOL.md §11.3 on sc/connect-m1 already says so. Default clients are unchanged. Multihop to a sidecar stays unsupported until someone needs it, which is then new work on option 2 with its first-Pack gap solved. design-records changes C3's citation from connect/transport_p2p.go:2345-2347 to `Client.run`, where the rule lives (`MatchesReceive` never sees a frame).

Changes: §4.6 C3 citation.

Questions: `connect-m1-multihop-endpoint.md`.

### QD-417: Citations that have drifted
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §11, §19.*

Records pass: run.sh's virustotal is at :2263 and notarize at :2649; §4.3's "None has a `sidecar` branch" and its hook sentence are history. §4.18's "x/text bump" needs no task, since every module is on v0.43.0, so `xTextIsNormalizerOnes` is on. §19.16's "the bundle filter (§4.8)" cites D-OPS-16 (OPS-M0-01). C3's `transport_p2p.go` citation is raised in connect-m1-multihop-endpoint.

Changes: §4.3; §4.7; §4.18; §11.14; §19.16.

Questions: `plan-REPO-small-readings.md#14`.

### QD-431: The macOS bundle
*Proposed fill: a gap the agents filled; work builds on it.*

`ur.app`, id `network.ur.cli`, at `/usr/local/lib/ur/ur.app`, with `/usr/local/bin/ur` and `/usr/local/bin/git-remote-ur` as links to its executable. One `.pkg` and one `.tar.gz` per architecture, no universal binary.

Changes: §4.10.

Questions: `plan-REPO-small-readings.md#7`.

### QD-453: Artifact names
*Proposed fill: a gap the agents filled; work builds on it.*

`ur-<version>-<os>-<arch>.tar.gz` and `.pkg`, `ur_<version>_<arch>.deb`, `ur-<version>.<rpmarch>.rpm`, `ur-<version>-<pkgarch>.pkg.tar.zst`, `ur-<version>-windows-<arch>.zip`, following build/all/linux/README.md's spellings. 14 files for six targets.

Changes: §4.10.

Questions: `plan-REPO-small-readings.md#9`.

### QD-486: Signature names
*Proposed fill: a gap the agents filled; work builds on it.*

Namespace `ur-release`, identity `ur-release`, public key at `sidecar/RELEASE-KEY.pub` and `https://ur.io/recurd/release-key.pub`. Before the key exists neither file does, and `install.sh` refuses.

Changes: §4.10.

Questions: `plan-REPO-small-readings.md#10`.

### QD-507: Build flags
*Proposed fill: a gap the agents filled; work builds on it.*

`GOEXPERIMENT=greenteagc` and `-ldflags "-w -s"` beside §4.10's `CGO_ENABLED=0 -trimpath`, as `sn_cli_release` (build/all/run.sh:2461-2481) builds release binaries.

Changes: §4.10.

Questions: `plan-REPO-small-readings.md#13`.

### QD-531: Which seam carries the injected clock into the core and the engines?
*Proposed fill: a gap the agents filled; work builds on it. Also amends §22.*

Root interface `sidecar.Clock` in clock.go, on every leg: `Now() time.Time`, `After(time.Duration) <-chan time.Time`, `AfterFunc(time.Duration, func()) (stop func() bool)`. `ServiceHost.Clock` and `SidecarSettings.Clock` hold it, nil meaning real time. `sidecartest.Clock` becomes an alias. make check refuses direct wall-clock calls in non-test files of the root, `<svc>service`, `mcp/` and `device/`, with a dated exception list, id.go first.

Changes: §4.5; §22.8.

Questions: `plan-TEST-clock-seam.md#1`.

### QD-545: How engines read gates
*Proposed fill: a gap the agents filled; work builds on it.*

A root interface `ServiceGates`, held as `ServiceHost.Gates`; server implements it over `CurrentSidecarConfig`. §4.5 picks up the field.

Changes: §4.5.

Questions: `plan-OPS-small-readings.md#1`.

### QD-580: May a `sidecar` branch be opened in the `tests` repo?
*Settled by the agents from the design; work builds on it.*

Yes. Open `sidecar` from `main` in `tests`, locally with no push, so `track-new` can cut `sc/<track>`, and add `tests` to HANDOFF section 5's repo table and to §4.8's merge order after `build`. The hard limit on `tests/network-intensive-suite-lock.sh` still holds, so only fixture runs test these edits.

Changes: §4.8; HANDOFF section 5.

Questions: `plan-TEST-tests-repo-branch.md`.

### QD-596: The x/text bump §4.7 and §11.14 ask for has already happened
*Settled by the agents from the design; work builds on it. Also amends §11.*

No bump is needed. What remains is §4.7's `make check` rule, and from M10 any x/text bump is a new normalizer and a rebuild. design-records corrects the citations in §4.7, §11.14's tables row and HANDOFF.md's 9.9.

Changes: §4.7 versions (citation); §11.14 tables row (citation).

Questions: `plan-SEARCH-small-readings.md#1`.

<a id="s5"></a>
## §5 The Sidecar core

### QD-009: A copied token can bind a key of its own
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §7, §2, §19.*

[plan-CORE-binding-wire#2] sidecar_identity_binding.client_id is unique across every sidecar. POST /sidecar/bind refuses a second binding of a client, whatever its sidecar_id, with 409 client_bound, a byte-identical retry excepted. A binding must also carry the key in network_client_owner.client_public_key where that column is set (plan-TEAM-enroll-client-key). §5.6's re-registration after a restore stays gated on the projection admitting the identity key. [plan-TEAM-enroll-client-key] Keep §7.4's fallback and store the key. MG1 adds nullable `network_client_owner.client_public_key` (bytea, 32 B), written once by `POST /network/enroll`, deleted with its client; §7.7's field list and §2.8 api-4's owner rows add it (I-18). §7.4's rule reads: the client's newest sidecar_identity_binding key, else that column; with neither, refused. `POST /sidecar/bind` refuses a binding whose client_public_key differs from a non-NULL column, and a client_id binds once: a repeat succeeds only for equal bytes, which also covers re-registration after a restore. `model.SetClientPublicKey` stays out of this.

Changes: §5.5; §5.15; §7.4; §7.7; §2.8 api-4; §19.7 MG1.

Questions: `plan-CORE-binding-wire.md#2`, `plan-TEAM-enroll-client-key.md`.

### QD-010: The key derivation from a recovery code
*Decided by the owner: owner 2026-11-06. Also amends §10.*

follow Proposed as the rule. (The recommendation it replaces: From the 16 bytes E, not the words and with no BIP-39 PBKDF2 step: ed25519_seed = HKDF-SHA256(ikm = E, salt empty, info "urnetwork-sidecar-v1/recovery-ed25519", 32 bytes), and xwing_seed = the same with info "urnetwork-sidecar-v1/recovery-xwing", used as crypto/hpke's MLKEM768X25519().NewPrivateKey(xwing_seed). E is zeroed once both are derived, with testHookSecret at E and each seed. testdata/recovery/ pins a code to both public keys and a genesis_sig, byte-equal on every leg.)

Changes: §5.9; §10.8.

Questions: `plan-CORE-recovery-derivation.md#2`.

### QD-014: What makes an action high risk, and what a high-risk approval requires
*Decided by the owner: owner 2026-11-06. Also amends §8, §2, §16.*

the file's option 3: drop SSHSIGs from v0 and every milestone until a customer asks, leaving the field reserved, and R-MCP-7 changes to say so. So no decision needs an SSHSIG, an sshsig field is ignored and never trusted, and every action stays normal. This replaces Proposed. (The recommendation it replaces: Recommended: two levels, normal 1 and high 2. `risk(a, P)` = max(the matching rule's `risk`, `classifier(a)`), a pure function of the stored CanonicalAction and the pin, so approver, spender and gate compute it alike and `ApprovalRequest.risk` only reports it. `classifier(a)` is high for kind publish with audience public; kind mail_send with more than 10 recipients, a constant, since verifiers must agree; kinds dns_set and dns_delete with `dns_name` `@`; and kinds agent_config_write and agent_config_delete. Policy: `risk: high` on a `requests` rule, `uint32 risk = 10` in `AclRequestRule`, reserved before M2's Gn-in, with §2.8's api-7 naming it, since request rules are server-visible (I-18). A high-risk decision needs channel device or presence, never harness, since a same-uid agent can drive ssh-agent, plus the approver's SSHSIG. An approver with no live sshsig key cannot approve one and is told `ur keys add-ssh`, so a phone alone cannot.)

Changes: §5.4 SidecarRisk; §8.5 requests; §8.8 AclRequestRule; §2.8 api-7; §16.6 Approval channels.

Questions: `plan-MCP-risk-classifier.md#1`.

### QD-034: What an approved recipient is, who can see the list, and what evidence creates it
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §15, §16.*

Recommended: an approved recipient is a (sending alias, recipient address) pair with an approval record in the repo that holds that alias's mail, never in mailcfg: path `rcpt/<h>/<address>` in `mailbox:<member>` or the `group:<group>` repo, <h> as §15.7's shards. Body `MailRecipientApproval{alias, recipient, decision, action}`: the stored bytes of one ApprovalDecision on channel device or presence and of the CanonicalAction of kind mail_send listing that recipient. The daemon writes one record per recipient after that use's Outcome is done, created only if absent. Every device re-verifies the embedded decision at each use under its current pin (signer eligible, channel in the governing list), so a file an agent wrote, or one whose approver was revoked, approves nothing. A channel harness decision sends its one message and creates no record. A record lasts until a person removes it with `ur mail recipients rm` on /dev/tty or in an app; MCP's evs tools refuse `rcpt/`. `mail_send` is W only when every non-member recipient has a record and the run is untainted, else O; in a tainted run records are ignored (TS1).

Changes: §5.4 SidecarAction comment; §15.7; §15.10; §16.5 mail_send; §16.6 Taint.

Questions: `plan-MCP-approved-recipients.md`.

### QD-039: The safety number's bytes, length and display
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

digest = SHA-256("urnetwork-sidecar-v1/safety-number" || 0x00 || genesis_sha256 || identity_public_key), both 32 bytes, genesis_sha256 being SHA-256(Signed Genesis). N is digest read big-endian, and the number is N mod 10^60, zero-padded to 60 decimal digits, shown as 12 groups of 5 in three lines of 4 groups. ur and SidecarApprovals show it identically, with one vector byte-equal on every leg.

Changes: §5.6; §2.8 EX5; D-CORE-13.

Questions: `plan-CORE-safety-number.md`.

### QD-074: How does a re-formed group carry the ladder: which group_id, which bytes, which route, which checks?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §7, §10, §11.*

Option 1, with these rules. (1) A re-form draws a new 16-byte group_id, and GroupForm names previous_group_id and generation, the newest g the re-former holds. (2) Clients keep each verified GenRotate's Signed bytes beside RK_g in §5.9's key cache from v0's first generation, since a signature cannot be rebuilt later. (3) The new group's gen/<k>, k <= the form's generation, holds the old Signed GenRotate byte for byte, naming its old group_id; GenLink's AAD and C_g hold no group_id, so the ladder carries over. (4) New route POST /gkm/groups/<id>/ladder, admin scope, at most 64 Signed GenRotates a call in ascending order, open only while the newest GroupForm names the group and before its epoch/1 exists, and in re-seed mode with the form: gkm checks order, parent_commitment against gen/<k-1> and k <= the form's generation, writes each If-None-Match with equal bytes answering success, and skips the claim checks' time and signer rows. (5) The group takes no commit, wrap or claim until gen/<form's generation> exists. (6) Members check the form's signer by §10.6's rule and each C_k against their cached one, a mismatch being an alarm and no adoption, and judge each GenRotate's signature and §10.9's rotation checks only where their retained log reaches, as the judged row does. (7) For g <= the form's generation, delivery checks compare a body's group_id with the path's group, not gen/<g>'s. (8) Generation pins compare (g, C_g); a new group_id at an equal (g, C_g), and a new epoch pin from epoch 0, are taken only along a verified GroupForm chain, and evs and readers resolve a statement's gen/<g> through the repo's newest GroupForm. (9) Later rotations run as usual.

Changes: §5.9 key cache; §7.8 re-seed mode; §10.5 cache paragraph; §10.6 checks; §10.8 site loss; §10.9 delivery checks; §10.14 routes; §11.8 pins; D-KEYS-13.

Questions: `plan-KEYS-reform-ladder.md`.

### QD-085: How a first recovery code is created and shown
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §18, §7.*

ur login, once its device is admitted or has signed Genesis and base 1, and its member has no current binding, offers recovery setup on /dev/tty. ur keychain recovery-rotate runs the same path, signing RecoveryBind when the member has no binding and RecoveryRebind otherwise. The ur process draws the 16 bytes, derives both keys, computes genesis_sig from the network id and Genesis hash the daemon returns, prints the 12 words once on /dev/tty, and sends the daemon only the two public keys and genesis_sig to sign, under §7.9's presence row. Declining leaves no binding: keychain.wrap has no HPKE copy and ur status says so. §18.5 gains one seam for apps, CreateRecoveryCode on SidecarApprovals, which runs in process and hands the words to the host's UI, never over control mode.

Changes: §5.9; §5.8; §18.5.

Questions: `plan-CORE-cli-ui-missing.md#3`.

### QD-119: Whether public service urls may sit in code, given the brief's hard limit
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §18.*

Keep DefaultSidecarSettings' urls empty, so NewSidecar refuses until a host sets them, and have cli/ and sdk hosts fill them from §18.9's embedded host table, the one copy of these names (SDK-M4-07's data file, which needs this exception to the limit). §5.4's comment changes to 'set by the host from §18.9's table'. Tests stay on .example names.

Changes: §5.4; BRIEF hard limits.

Questions: `core-types-default-urls.md`.

### QD-120: How ur knows when to stop refusing beside a readable credential
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §7.*

No signal. The check is by state: ur refuses to enroll, and an enrolled daemon alarms at each start and at each SyncRefetchInterval, while a store holds a readable network by_jwt, whatever the stage. A host the releases cleaned passes by itself, and a later ur release drops the check once the fleet has moved. No reply field, config key or spoofable input.

Changes: D-TRUST-3; §5.6; §7.4.

Questions: `plan-CORE-host-store-refusal.md#1`.

### QD-121: The keychain's auto-lock: value, meaning of idle, and always-on daemons
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

AutoLockTimeout defaults to 10 minutes. Idle means no request on any local socket (control, mcp, hook, git) for that long, and it never applies while Daemon.ShouldIdleExit's busy rule holds: mail, sockets or bridge on, or an indexer. Locking drops U and every R_n and enters Locked. Where a key store holds U, the next local request runs Unlock(nil) by itself. Zero never locks, for a host to set on purpose.

Changes: §5.4; §5.8.

Questions: `core-types-auto-lock.md`.

### QD-148: No route maps a client id to its sidecar, or lists older generations
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §8.*

GET /sidecar/identity/<sidecar_id> keeps its fields and adds bindings: that sidecar's stored wrappers, newest first, 64 a page, ?before_generation=<g> for the next. Add GET /sidecar/identity?client_id=<id>, answering {sidecar_id, identity_public_key, identity_alg, status, binding} for that client's binding of any generation, 404 if none. Both are Client class under §5.15's caller rule, the caller's own network or one with an active §8.11 share, with wrappers in base64. Verifiers check both signatures and the identity key against their pin, so api stays untrusted. Callers: a replaying reader, only for a commit whose committer differs from its EvsPush.client_id, requiring the binding's sidecar_id to equal the push's signer_sidecar_id, with SidecarCommitter refusing what stays unresolved; plan-ACL-selector-resolution's writer; and BRIDGE-M4-16's compile for plan-BRIDGE-subject-resolution's client_ids. Never the packet path. api-5's lookups line adds the second route.

Changes: §5.15; §2.8 api-5.

Questions: `plan-CORE-client-to-sidecar-lookup.md#2`.

### QD-154: §11's conflict and its reader and writer alarms have no SidecarEvent kind to ride
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §18, §11.*

Option 1. Add two kinds to §5.4 and §18.5, beside sidecar_types.go's list. evs_conflict: RepoId, RefId and Path, the local conflict ref; §11.11's restart row raises it, and it is an ordinary event. evs_alarm: RepoId, RefId, Path, SidecarId as the signer, and a new field EvsAlarm with the closed reasons missing_segment, tamper (a failed entry hash, AEAD, oid or statement), version_rule (off §11.7's rule), epoch_overdue (a writer, 1 h past due_by_ms) and prefix_rule (from M6). A head not extending a pin stays head_alarm with HeadAlarm fork, SidecarId nil and Evidence holding this device's RefHead and evs's. record_alarm (plan-RECORD-alarm-kinds) keeps chain, path-rule and depositor alarms.

Changes: §5.4 SidecarEvent; §18.5 AddEventListener.

Questions: `plan-EVS1-evs-events.md`.

### QD-159: How a reader learns and checks an agent subkey
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §6, §11.*

The identity key signs AgentCert{sidecar_id, agent_id, public_key, not_after_ms}, not_after_ms at most 30 days after signing, as a typed Signed with purpose agent-cert and SIGNED_AGENT_CERT = 0x1A02. That Signed rides inside the sealed provenance it vouches for: AgentSignedBody (RECORD.md 5.3) and a push's sealed metadata (§11.6), never a log statement or config record. A reader checks the certificate under the identity key of the sidecar that signed the carrying entry, that the entry's time is before not_after_ms, then the subkey's signature. A bad signature alarms; an absent certificate reads agent_asserted.

Changes: §5.5; §6.9; §6.11; §11.6; RECORD.md 5.3.

Questions: `plan-CORE-agent-revoke.md#1`.

### QD-160: §5.4's Authorize cannot carry an effect in or an outcome out, though §16.6 runs the effect inside it
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §16.*

Take option 1 with these shapes in §5.4. `SidecarAction` gains `Effect SidecarEffect`, live and set by the caller, and `Outcome *SidecarOutcome`, set by Authorize. `type SidecarEffect interface { Run(ctx context.Context, effectKey []byte) (effectRef []byte, err error) }`, idempotent per key, the key empty under a standing grant. `SidecarOutcome{State: done | not_done | uncertain, EffectRef []byte}`. `func (self *Sidecar) RegisterEffectLookup(kind SidecarActionKind, lookup SidecarEffectLookup) func()`, with `SidecarEffectLookup func(ctx context.Context, canonical []byte, effectKey []byte) (*SidecarOutcome, error)`, which reads only the stored action, so restart reconciles with no caller alive. Authorize keeps its signature and runs §16.6's steps 1 to 6, or under a standing grant the effect with an empty key and no ledger row. It returns nil once an Outcome exists, `*ApprovalPendingError` for pending, and any other error for a refusal. A retry returns the recorded Outcome without calling Run unless that outcome is uncertain. The approval's mutex covers steps 1 to 4 only, never Run. A kind with no registered lookup is refused before its Reserve. `SidecarEnv.Authorize` takes the same action, and §5.4's gate paragraph says Authorize runs the effect.

Changes: §5.4 SidecarAction; §5.4 SidecarEnv; §5.4 Outward-action gate; §16.16 Provides.

Questions: `plan-MCP-effect-seam.md`.

### QD-168: No SidecarEvent kind carries the record's and the directory's reader alarms
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §18, §16.*

Add one kind to §5.4's SidecarEventKind and §18.5's list: `record_alarm`, with a new field `RecordAlarm SidecarRecordAlarm` beside `HeadAlarm`, using the existing `RepoId` and `SidecarId` (the writer or signer). Its closed reasons are 14: chain_gap, chain_fork, bad_entry (RECORD.md section 5.4 steps 1-4, section 5.5 steps 1-3, 5 and 6), depositor_kind, early_removal (a BASE or ERASE taking an entry before keep_days, or a class 7 entry), path_rule, parked_writer, over_cap, over_limit (§16.11's limits row), id_reuse (plan-RECORD-small-readings #2), bad_erasure (an ERASE, CUT or CLOSURE from another signer, or an erasure_request that fails its check), bad_decision, log_check (RECORD.md section 10.2) and moderation, which apps show as a notice. `head_alarm` stays HeadCheck's and `index_mismatch` the index's. plan-EVS1-evs-events' `evs_alarm` stays separate, for storage tampering.

Changes: §5.4 SidecarEventKind and SidecarEvent; §18.5 AddEventListener list; RECORD.md section 18's §5.4 ask.

Questions: `plan-RECORD-alarm-kinds.md`.

### QD-183: Which stores the check reads, and how
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

hostCredentialStores reports a store only if this user can read it and it holds a token, and never copies, logs or sends a value. App: under %LOCALAPPDATA%\URnetwork, $XDG_STATE_HOME/urnetwork, ~/Documents and the Documents of the macOS containers network.ur and com.bringyour.urnetwork, any .by/.auth_state whose JSON by_jwt is non-empty, or a non-empty legacy .by/.by_jwt. Extension: a Chrome, Chromium, Edge or Brave profile's Extensions/*/*/manifest.json naming URnetwork, or a Firefox profile's extensions.json naming urnetwork@bringyour.com, at a version below D-SDK-11's first non-persisting release, a constant that stays unset, so every version counts, until that release ships. No extension's storage is opened and no LevelDB or IndexedDB is parsed.

Changes: §5.6.

Questions: `plan-CORE-host-store-refusal.md#2`.

### QD-226: §5.9, §7.9 and §10.8 understate what a keychain backup yields
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §7, §10.*

Replace "identity key, ClientKey seed, ReaderKeys and key cache" in §5.9's Backup bullet, §7.9's after row and §10.8's rebind bullet with: all of keychain.ur (client jwt, ClientKey seed, identity and agent keys, ReaderKeys, a Delegation's reader key, unlanded statements and §10's key cache) and, by keys derived from R_n, approvals/, runs/, restore/ and component state.

Changes: §5.9; §7.9; §10.8.

Questions: `g0-recheck-2-compromise-rebind-backups.md#2`.

### QD-232: What AgentRevoke is, given that a subkey never leaves the daemon
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Make AgentRevoke a local act, not a record. Sidecar.AgentRevoke(agentId) deletes the subkey from keychain.ur and the daemon signs nothing more with it. Readers bound a subkey by its certificate's not_after_ms, at most 30 days. A compromised daemon is a SidecarRevoke{reason: compromise}, and provenance from its since_n on reads unattributed. §5.5's phrase becomes 'ended by a local AgentRevoke and by not_after'. No proto number needs reserving at M2.

Changes: §5.5; D-CORE-6.

Questions: `plan-CORE-agent-revoke.md#2`.

### QD-253: 'Shown as verified since <time>' has no interface to travel on
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §18, §11.*

Define the seam only, no UI (owner rule 6). The pin record holds the time of the newest re-pin past the budget. §5.4's SidecarEvent gains kind evs_gap with RepoId, RefId and VerifiedSince time.Time, raised at each re-pin and relayed by §18.5, beside whatever kinds plan-EVS1-evs-events settles. EvsRepo.VerifiedSince(refId) time.Time, zero when nothing was skipped, serves a later view, and SidecarEvs.VerifiedSince mirrors it for apps.

Changes: §5.4 SidecarEvent; §18.5; §11.9 budget row.

Questions: `g0-recheck-0-head-reader-read-paths.md#3`.

### QD-283: The recovery code's word encoding
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The 12 words are BIP-39 of 16 random bytes with its standard 4-bit checksum (first 4 bits of SHA-256 of the 16 bytes), on the English list, embedded in the root so it gains no module. A bad checksum refuses at entry.

Questions: `plan-CORE-recovery-derivation.md#1`.

### QD-293: A binding's generation
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A sidecar_id's first binding has generation 1 and creates its sidecar_identity row. Each later one is the newest plus one and must carry that row's identity_public_key, else 409 generation_conflict.

Questions: `plan-CORE-binding-wire.md#3`.

### QD-299: Implicit MX
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

With no MX RRset and no null MX, RFC 5321 §5.1's fallback to the domain's address applies, `mx_host` is the domain, and DANE uses that host. NO_MX answers only when no address exists either.

Questions: `plan-SMTP-small-readings.md#13`.

### QD-324: The token must match the binding
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The bearer token's client must equal the binding's client_id and its network the binding's network_id, else 400 binding_invalid, which also answers a bad signature or a malformed body.

Questions: `plan-CORE-binding-wire.md#4`.

### QD-365: What zero means in a settings number
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

SidecarSettings.validate refuses every number that is not positive on every leg, so zero is never unlimited or off. Only fields tagged settings:"zero" give zero a meaning, stated in their comment: CacheByteCount (in memory), AutoLockTimeout (never), IdleExitTimeout (never). Tests set small positive values.

Questions: `core-types-open-default-numbers.md#7`.

### QD-413: R-SDK-9's 'start a local device that listens'
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

§5.8's spawn of `ur daemon` satisfies R-SDK-9. `NewSidecarRemote` with no daemon reports `offline` and embeds no local one.

Questions: `plan-SDK-small-readings.md#9`.

### QD-429: Numbers for the uint32 values inside CanonicalAction, ApprovalRequest and ApprovalDecision
*Proposed fill: a gap the agents filled; work builds on it. Also amends §16, §15.*

RECORD-M2-01 declares four enums in protocol/record.proto; the fields stay uint32 as §16.8 writes them, and 0 is UNSPECIFIED, written by no one. `SidecarActionKind`, in §5.4's order, one verb a value, `restore` appended: 1 publish, 2 listen, 3 forward, 4 expose, 5 egress_change, 6 invite, 7 share, 8 alias_create (burners too, §15.8), 9 alias_delete, 10 agent_config_write, 11 agent_config_delete, 12 dns_set, 13 dns_delete, 14 mail_send, 15 access_request, 16 payment, 17 restore; new kinds append. publish and listen cover tls/ and smtp/ alike, since `host` and `socket_name` say which. `SidecarRisk`: 1 normal, 2 high, numeric order being the max §5.4 takes. `ApprovalVerdict` (`decision`): 1 approve, 2 deny. `ApprovalChannel` (`channel`, and `AclRequestRule.evidence`): 1 device, 2 presence, 3 harness, as RECORD.md section 6.2. `audience` and `app_mode` hold acl.proto's `AclAudience` and `AclAppMode`: a publish's action always writes the resolved non-zero value (members 1, http 1), and a gate maps a request's 0 to 1 before comparing. An approver, spender or gate refuses 0 or an unknown value of any of these; §16.8's "unknown kinds are kept" covers `RecordHeader.kind` only. CORE-M1-01's Go types take these values. Kinds 5, 6, 7 and 16 have no O tool and no row in MCP-M3-02's kind table, so `NewCanonicalAction` refuses each until its owner names its fields. §5.4 and §16.8 record the table at M3's Gn-in.

Changes: §5.4 SidecarAction; §16.8 CanonicalAction, ApprovalRequest, ApprovalDecision; RECORD.md section 6.2.

Questions: `plan-MCP-wire-enum-numbers.md`.

### QD-433: SidecarIdentityBinding's message, home, signatures and carrier
*Proposed fill: a gap the agents filled; work builds on it. Also amends §6.*

In protocol/bridge/auth.proto: message SidecarIdentityBinding { bytes network_id = 1; bytes sidecar_id = 2; bytes client_id = 3; int64 generation = 4; bytes client_public_key = 5; bytes identity_public_key = 6; int64 issued_at_ms = 7; } and message SignedSidecarIdentityBinding { bytes body = 1; bytes client_signature = 2; bytes identity_signature = 3; }, body being the first message's bytes. Each signature is Ed25519 over §6.9's signed bytes with SIGNED_SIDECAR_BINDING = 0x1A01: purpose binding-client by the ClientKey, binding-identity by the identity key. Verifiers check the received body bytes, never a re-marshal. Hello.binding and POST /sidecar/bind carry the marshalled wrapper, and §5.15's signatures column stores those bytes verbatim, since the table's other columns cannot rebuild them.

Changes: §5.4; §5.15; §6.5; §6.9; §6.11.

Questions: `plan-CORE-binding-wire.md#1`.

### QD-434: CORE_HINT's message
*Proposed fill: a gap the agents filled; work builds on it. Also amends §6.*

In protocol/core.proto: message CoreHint { CoreHintKind kind = 1; bytes sidecar_id = 2; uint32 min_secure_version = 3; } with enum CoreHintKind { CORE_HINT_KIND_UNSPECIFIED = 0; CORE_HINT_KIND_REVOCATION = 1; CORE_HINT_KIND_RESYNC = 2; CORE_HINT_KIND_WAKE = 3; CORE_HINT_KIND_MIN_SECURE = 4; CORE_HINT_KIND_GATES = 5; }. PushHint.kind is 0x1A01 and PushHint.hint the marshalled message, under 256 B. sidecar_id is this client's own, set only on REVOCATION; min_secure_version only on MIN_SECURE. An unknown kind or a dropped body is a bare resync, and no field carries authority (§5.6).

Changes: §5.15; §6.11.

Questions: `plan-CORE-core-hint-body.md#1`.

### QD-438: POST /sidecar/bind's body, reply and refusal shape
*Proposed fill: a gap the agents filled; work builds on it.*

Request: JSON {"binding": "<base64 of the wrapper>"}. Reply: 200 {"generation": n}. A refusal uses the server's existing coded body, {"error": "<text>", "code": "<code>"}: 403 sidecar_revoked, 400 binding_invalid, 409 generation_conflict, 409 client_bound. The question's {error: {code}} is not a shape server or sdk reads today.

Changes: §5.15.

Questions: `plan-CORE-binding-wire.md#6`.

### QD-454: --port's default
*Proposed fill: a gap the agents filled; work builds on it.*

ur daemon --port defaults to 17000, the first of the local services in this order: git http or https 17000, git ssh 17001, submission 17002, IMAP 17003. A second instance on one host passes its own --port, and a taken port fails naming the flag. Set it once in SidecarLocalSettings.FirstPort.

Changes: §5.8.

Questions: `plan-CORE-cli-ui-missing.md#6`.

### QD-455: Which command takes --replace
*Proposed fill: a gap the agents filled; work builds on it.*

ur login --replace, and ur connect --token <key> --replace: on a restored state directory whose machine-id hash differs, keep sidecar_id and identity key, bind generation n+1 on the new client, and remove the old client.

Changes: §5.9.

Questions: `plan-CORE-cli-ui-missing.md#4`.

### QD-472: The event an enrolled daemon raises
*Proposed fill: a gap the agents filled; work builds on it. Also amends §18.*

Add credential_store to §5.4's SidecarEventKind and §18.5's mirror, with no path or value in the event; ur status names the store kind.

Changes: §5.4; §18.5.

Questions: `plan-CORE-host-store-refusal.md#3`.

### QD-483: Proving memory exceeds §5's budget
*Proposed fill: a gap the agents filled; work builds on it. Also amends §6.*

Proving sits outside `MemoryBudgetByteCount`, which bounds §6's caps. `SmtpSenderSettings.ProverConcurrency` defaults to 1. A host records `p/` only after `Prover.Measure` finishes its largest shape; one that cannot records none and only queues.

Changes: §5.4 settings.

Questions: `plan-SMTP-small-readings.md#19`.

### QD-504: A retry of the same binding
*Proposed fill: a gap the agents filled; work builds on it.*

A POST whose wrapper bytes equal the stored row's answers 200 with that generation and writes nothing. Any other bytes for a bound client answer 409 client_bound.

Questions: `plan-CORE-binding-wire.md#5`.

### QD-508: The pass-change command, and whether ur lock exists
*Proposed fill: a gap the agents filled; work builds on it.*

ur keychain pass rewraps U under a new pass read from /dev/tty. ur lock exists: it drops U and every R_n from memory at once, as auto-lock does, and needs no confirmation, since it only narrows.

Changes: §5.9.

Questions: `plan-CORE-cli-ui-missing.md#2`.

### QD-509: The command a code-only recovered device runs
*Proposed fill: a gap the agents filled; work builds on it.*

ur login --recover, reading the 12 words only from /dev/tty, as the pass is, never argv, env or stdin.

Changes: §5.9.

Questions: `plan-CORE-cli-ui-missing.md#5`.

### QD-511: The companion push cadence is one setting, since a client cannot see the store's block size
*Proposed fill: a gap the agents filled; work builds on it.*

Add `Search.CompanionInterval time.Duration` to §5.4, default 5 min on every host. When D-TEST-11's M2 run fixes 1 KiB blocks, DefaultSidecarSettings moves it to 1 min. No server signal carries it.

Questions: `plan-SEARCH-small-readings.md#6`.

### QD-512: Where the CT watch's alarm surfaces
*Proposed fill: a gap the agents filled; work builds on it.*

SidecarEventKind gains ct_alarm, with Evidence[0] the leaf's SHA-256. SidecarStatus gains CtWatchDegraded bool.

Changes: §5.4.

Questions: `plan-TLS-small-readings.md#13`.

### QD-514: ComponentQueueByteCount
*Proposed fill: a gap the agents filled; work builds on it.*

1 MiB, 256 envelopes in their 4 KiB pool class. A reassembled body counts by its size, so one 256 KiB body takes a quarter of the queue.

Questions: `core-types-open-default-numbers.md#5`.

### QD-516: LocalSettings.IdleExitTimeout
*Proposed fill: a gap the agents filled; work builds on it.*

10 minutes; zero never exits. Only an auto-spawned daemon counts it, and busy or unit-run daemons never idle out (§5.8).

Questions: `core-types-open-default-numbers.md#1`.

### QD-518: LocalSettings.RequestTimeout
*Proposed fill: a gap the agents filled; work builds on it.*

30 seconds for a local request's own work. Time waiting on a person is outside it: a /dev/tty confirmation and the daemon's presence prompt run under the method's own bound, and git-mode streams and MCP sessions keep theirs (Mcp.CallTimeout).

Questions: `core-types-open-default-numbers.md#3`.

### QD-534: §5.4 has no alarm kind for D-MAIL-15
*Proposed fill: a gap the agents filled; work builds on it.*

Add `mail_receiver_alarm` to `SidecarEventKind`, with `SidecarId` the receiver and `RepoId` the repo.

Changes: §5.4.

Questions: `plan-MAIL-small-readings.md#8`.

### QD-550: `ur status` lines for unmirrored logs and waiting erasures
*Proposed fill: a gap the agents filled; work builds on it.*

`SidecarStatus` gains `Lines []string`, one line per condition, filled by each component through CORE's status seam and printed by `ur status` as is. Nothing parses them.

Changes: §5.4 SidecarStatus.

Questions: `plan-RECORD-small-readings.md#13`.

### QD-557: SidecarEvent kind for bridge alarms
*Proposed fill: a gap the agents filled; work builds on it. Also amends §18, §17.*

Add `bridge_alarm` to §5.4's `SidecarEventKind` and §18.5's listener comment, with a string `BridgeAlarm`: `block_conflict` (§17.4), `share_holder_removed` (§17.9), `principal_mismatch` (§17.9's verify), `state_unverified` (§17.8) or `block_refused` (D-BRIDGE-16).

Questions: `plan-BRIDGE-small-readings.md#17`.

### QD-572: Names for §5.4's partitions, §16.10's breadth and §22.4's oracle scope
*Proposed fill: a gap the agents filled; work builds on it. Also amends §16, §22.*

SearchScope stays §5.4's partitions (SearchCached, SearchLatest, SearchAll). §16.10's breadth is `SearchBreadth` with values SearchBreadthRepo, SearchBreadthNetwork and SearchBreadthAll. §22.4's parameter is `sidecartest.SearchScope`, a struct holding one of each, declared in sidecartest. search.proto's `scope` keeps its own 1 and 2.

Questions: `plan-SEARCH-small-readings.md#8`.

### QD-578: A commit under its push's own client needs no lookup
*Settled by the agents from the design; work builds on it.*

A replaying reader compares a new commit's committer with <client_id>@ur.invalid taken from that push's own EvsPush.client_id, under the signature it already verifies. Equal passes with no lookup. A committer that differs is #2's case.

Questions: `plan-CORE-client-to-sidecar-lookup.md#1`.

### QD-593: A bare key beside a tagged key of the same name
*Settled by the agents from the design; work builds on it.*

Refuse: each key of a multi-key call carries the one shared tag, and a single key needs none. RedisKeysShareTag does this.

Questions: `core-types-bare-key-tag.md`.

<a id="s6"></a>
## §6 The sidecar subprotocol

### QD-032: An unsigned minimum-version raise could cut every peer
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §5.*

[plan-CORE-core-hint-body#4] An unsigned raise is a live denial, not stored state. A device applies min(the floor GET /sidecar/sync/core currently reports, its own compiled secure_version), never persists it, and keeps the compiled MinSecureVersion as the lower bound. A value above its own version prompts an upgrade through ur status. §2.8 discloses the floor under I-4 as a denial. Same issue as plan-PROTO-small-readings' item 7. [plan-PROTO-small-readings#7] Recommended, in place of the reading: an unsigned raise is a live denial, not stored state. A device applies the floor `GET /sidecar/sync/core` currently reports, as min(raised floor, its own compiled secure_version), never below the compiled MinSecureVersion, and persists nothing. A forged floor then never refuses a peer at this device's version or newer, and it ends when the operator stops asserting it. A value above the device's own version prompts an upgrade through ur status. §2.8 discloses the raise under I-4 as a denial. plan-CORE-core-hint-body.md#4 is the same rule.

Changes: §6.4; §2.8; §5.15.

Questions: `plan-CORE-core-hint-body.md#4`, `plan-PROTO-small-readings.md#7`.

### QD-045: Whether same-network P2P is on by default once tested
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §17, §2.*

Recommended: build at M6 behind SidecarProtocolSettings.EnablePeerP2p, default off, keeping relay-only until a later owner call made on FS-126 and measurement. Before any network turns it on, §2.8's connect rows and §2.10 gain: a pair on P2P learns each other's public addresses through ICE, and relays see no frames of that pair. §6.18's line becomes "able to end relay-only".

Changes: §6.18; §17.18; §2.8 connect-2; §2.10; D-PROTO-10.

Questions: `plan-PROTO-p2p-milestone.md#3`.

### QD-093: Where a recovery-signed statement carries its key, and what signer_id and key_id hold
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §7.*

Keep what landed. §6.9's Signers adds: a member's recovery key has signer_id = member_id and key_id = the raw 32-byte Ed25519 key, which bridge.VerifyRecoverySigned matches to MemberRow.recovery_key_sha256; a Delegation key has signer_id = delegation_id and key_id = SHA-256 of Delegation.pubkey. An identity key leaves key_id empty. A verifier picks the path from those lengths (16 and 0 a sidecar, 16 and 32 a member's recovery key, 32 and 32 a Delegation), never by trying keys, so a sidecar_id chosen equal to a member_id confuses nothing. api-7 adds 'a recovery-signed statement's recovery Ed25519 public key'.

Changes: §6.9; §2.8 api-7; §7.9.

Questions: `protos-bridge-recovery-key-carrier.md`.

### QD-146: How does gkm turn a sidecar_id into the client id that §6.8's per-client hints need, with no Postgres?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §10, §19, §2, §5, §22.*

Option 1, on the seam already landed, Push.HintSidecars in host_push.go, with two host implementations. taskworker, which may read Postgres, resolves from sidecar_identity_binding. server/cli/gkm, and any other host that keeps Postgres off this path, as mxedge's router does under plan-MAIL-hints.md#2, calls a new internal api route, POST /sidecar/identity/clients {sidecar_ids, at most 1,000}, answering each id's current client_id and generation and omitting unknown or revoked ids, under the internal-route credential plan-TLS-internal-credentials settles. Each such process keeps a map with a 5-minute TTL and at most 65,536 entries; a miss batches one call, and a failed call returns an error that gkm counts and passes over, since §6.8's hourly resync covers a lost hint. No new store or Redis family, and §22.7's "no Postgres" holds. §19.4's gkm row gains api reach and the credential, and api-5's lookups line names the route, which logs no per-target record.

Changes: §6.8; §10.14; §19.4 gkm row; §2.8 api-5; §5.15 routes.

Questions: `plan-KEYS-hint-addressing.md`.

### QD-149: Sync routes promise versions no one stores
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §5, §13, §15, §20, §19.*

[plan-CORE-core-hint-body#3] §6.8's registry row becomes: core, §5, api's clock in µs, which the script raises to the stored value plus one, by HINCRBY, when not above it, as gkm's. A client treats a fall as a gap. {scp_<C>}ver lives at most 1 h, so a client fetches GET /sidecar/sync/core at each reconnect and hourly resync whatever versions shows. No table or §19.10 step. This is the core slice of plan-PROTO-sync-routes-durable-versions, whose row takes the same clock. [plan-PROTO-sync-routes-durable-versions] Only topics that gate access stay durable. §6.8's registry becomes: team = the authorization log position n; dns as written; core = api's clock in µs (plan-CORE-core-hint-body.md#3); mail = the writer's clock in ms per client (plan-MAIL-hints.md#3); tls the same as mail; each clock raised past the stored value by HINCRBY as gkm's is; sock, gkm and evs as written. A clock version's fall is a gap, so no §19.10 step is needed, and §6.16's "every other Postgres-held topic version" goes. `GET /sidecar/sync/versions?cursor=` answers 200 PollResponse with `reset` set and no hints, at most 48 versions a page, complete = false and a cursor until the last: team from network_acl_head, dns from its serial, core from {scp_<C>}ver or else api's clock, so an hourly resync always fetches core, and the rest from {scp_<C>}ver, omitting what has expired, which a client keeps. `GET /sidecar/sync/<topic>?since=` serves `core` only, with plan-CORE-core-hint-body.md#2's body; other topics answer 404 and use their owners' routes (§6.8's "the owner's API"). A limit change on `team` raises no n and reaches clients at the hourly resync. This differs from the question's option 1: core cannot use n, and tls and mail need no counters.

Changes: §6.8; §6.16; §2.8 connect-4; §5.15; §13.15; §15.15; §20.14.

Questions: `plan-CORE-core-hint-body.md#3`, `plan-PROTO-sync-routes-durable-versions.md`.

### QD-150: Clients can disagree on a window's first contract
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §4.*

[plan-SEARCH-c19-first-contract] A window's first contract is the lowest contract id, compared as bytes, among that direction's window contracts that carried at least one frame by this client's count, sent or received. Contract ids are server-minted ULID-shaped ids both sides hold. A contract no frame rode reports 0, and `reports`' 'creation order' past the first grant means ascending contract id. Adoption is by lane, as connect-c19-window-first-contract words it, so the contract the Hello rode belongs to the up window. Connect adds `NotePeerWindowActivity(peerId)`, called by the sidecar on each Ping, Pong, Hello and HelloResult, which feeds `end`'s 'no Ping or Hello in its last 2 min' while connect stays generic. No wire change. A frame lost at a window's very start can still split the two reports; that is accepted. Fold this into PROTO-M10-02 and PROTO-M10-03 before they start. [connect-c19-window-first-contract] A window's first contract is the earliest-created contract a frame rode, adopted by lane through `AdoptPeerWindowContract`, not every current receive contract. The requester's sidecar also adopts the HelloResult's lane, which pins that contract as the window's first; receive contracts registered before it leave the window and report exactly. About 20 lines in the ledger and one call in PROTO-M10-04. No wire change.

Changes: §6.10 window row; §6.10 reports row; §6.10 end row; §4.6 C19; FS-125; §6.10 window, reports rows; §4.6 C19.

Questions: `plan-SEARCH-c19-first-contract.md`, `connect-c19-window-first-contract.md`.

### QD-267: D-PROTO-18 gives parked and suspended sidecars a control contract the gate refuses
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §8.*

§8.10 governs: the gate issues a `control` contract only to two admitted sidecars of one network, neither revoked, parked nor suspended. Put those words in D-PROTO-18 (06-PROTO.md:638), §6.4's control contracts bullet (06-PROTO.md:98) and connect-1's `why` (02-TRUST.md:168, a copy the question missed).

Changes: D-PROTO-18; §6.4; §2.8 connect-1.

Questions: `g0-density-text-alignments.md#1`.

### QD-290: What ends Hello and partial-chunk state, when connect signals no sequence exit
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Hello state ends at HelloCacheTimeout, at any change of C15's key, checked per frame, or on a send's ack error. A partial message ends at ReassemblyIdleTimeout or when index 0 of its group arrives again, which restarts the group. Reword §6.6's comment and §6.5's chunk rule to these events.

Changes: §6.5; §6.6.

Questions: `plan-PROTO-small-readings.md#1`.

### QD-307: How a resident learns a client's sidecar marks
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A resident reads strict_exp and acl_enforcing from network_client_owner once at construction, in its existing profile read, and hosts a publisher on that.

Questions: `plan-PROTO-small-readings.md#6`.

### QD-314: §6.6's comment calls the 24 h witness alarm per-network config
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The 24 h alarm is a protocol constant, neither a ServiceSettings field nor a local setting. witness_bound_hours stays the only per-network value. Reword §6.6's comment: the stop at witness_bound_hours is per-network config, and the 24 h alarm is fixed by owner decision 129.

Changes: §6.6.

Questions: `plan-PROTO-small-readings.md#3`.

### QD-427: The down window opens on the HelloResult answering a bit-1 Hello, whatever bits it sets
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

In §6.10's window row 'bit-1' qualifies the Hello only: the down window opens with the contract carrying the HelloResult that answers a bit-1 Hello, whatever bits it sets, and an indexer never sets bit 1. Where the app host's own HelloResult carries bit 1, because the indexer said Hello first, that frame opens the up window and the indexer's next frame the down one.

Changes: §6.10 window row (wording).

Questions: `plan-SEARCH-small-readings.md#3`.

### QD-435: GET /sidecar/sync/core's reply
*Proposed fill: a gap the agents filled; work builds on it. Also amends §5.*

JSON {"version": "<decimal>", "min_secure_version": n, "gates": ["evs", ...], "revoked": bool}. gates is SidecarConfig.GatesFor(the token's network). revoked is whether api holds this sidecar revoked, a candidate the client verifies against the config (§5.6). It names no other sidecar, since a client serves one sidecar and the question's list adds nothing. It always answers 200.

Changes: §6.8; §6.16.

Questions: `plan-CORE-core-hint-body.md#2`.

### QD-436: Envelope details: Cancel, MORE, NO_REPLY, chunk headers and result messages
*Proposed fill: a gap the agents filled; work builds on it.*

CANCEL is an envelope of type 0x0005 naming the call in request_id, with no body and flag NO_REPLY. MORE (4) is set on every chunk but the final. NO_REPLY (8) is set on Cancel and on stream frames. Every chunk repeats type, flags apart from MORE, request_id and timeout_ms, and a mismatch drops the group. HelloResult and HeadCheckResult are separate messages with the same fields and numbers, as protocol/envelope.proto landed.

Changes: §6.5; §6.6.

Questions: `plan-PROTO-small-readings.md#4`.

### QD-437: PushReset.epoch's value, and seq's meaning when n expires
*Proposed fill: a gap the agents filled; work builds on it. Also amends §18.*

PushReset.epoch is any value unique per run for that client; publishers use the resident's start time in ms. seq is the INCR value: the script runs INCR before XADD and stores seq in the entry. n restarts at 1 when its 1 h key expires, so any seq but last + 1, a lower one included, is a gap and sends the client to `versions`. Align §6.8's diagram and §18.7's step 1, which write XADD before INCR.

Changes: §6.8; §18.7.

Questions: `plan-PROTO-small-readings.md#5`.

### QD-440: Row (j): what identity_signature signs
*Proposed fill: a gap the agents filled; work builds on it. Also amends §10.*

SIGNED_UR_MLS_CREDENTIAL = 0x1306, by §6.11's SIGNED_<MESSAGE> rule, purpose mls-credential. Signed bytes are "urnetwork-sidecar-v1/mls-credential" || 0x00 || u32be(0x1306) || body, body being the credential's received bytes before field 8's tag. A credential must encode fields 1 to 7 in ascending order with no unknown field, then field 8 last with nothing after it, or it is refused. Verify that prefix, never a re-marshal.

Changes: §6.9 purposes; §6.11 SignedType comment; §10.4 credential.

Questions: `plan-KEYS-wire-gaps.md#10`.

### QD-446: SignedType values
*Proposed fill: a gap the agents filled; work builds on it. Also amends §8, §7, §5.*

Ratify as landed: 0x1101 to 0x110F in §8.8's row order and 0x1201 to 0x1215 in §7.9's. §5 takes 0x1A01 SIGNED_SIDECAR_BINDING and 0x1A02 SIGNED_AGENT_CERT.

Changes: §6.11.

Questions: `protos-bridge-unwritten-numbers.md#4`.

### QD-447: SignedType values for §9, §10 and §11, with §6.11's 0x14xx list as a prefix of §11.6's four
*Proposed fill: a gap the agents filled; work builds on it. Also amends §9, §10, §11.*

As landed: SIGNED_SOCKET_REGISTRATION 0x1001, SIGNED_SOCKET_TICKET 0x1002; SIGNED_GEN_ROTATE 0x1301, SIGNED_READER_KEY 0x1302, SIGNED_READER_WRAP 0x1303, SIGNED_DELEGATION_WRAP 0x1304; SIGNED_EVS_PUSH 0x1401, SIGNED_EVS_RESEED 0x1402, SIGNED_EVS_PATH_MAP 0x1403, SIGNED_EVS_IMPORT 0x1404. Add SIGNED_GROUP_FORM 0x1305 and SIGNED_UR_MLS_CREDENTIAL 0x1306, as plan-KEYS-wire-gaps.md#1 and #10 answer rows a and j. Correct §6.11's comment to name all four evs statements.

Changes: §6.11.

Questions: `protos-services-unwritten-numbers.md#1`.

### QD-459: Where Error{VERSION} carries the receiver's version range
*Proposed fill: a gap the agents filled; work builds on it. Also amends §2.*

Add `uint32 min_version = 5; uint32 max_version = 6;` to Error in §6.5's fence and protocol/envelope.proto, set only on ERR_VERSION, with Hello's meaning. The fence and the proto change together, as TestDeclarationsMatchTheirFences requires. No §2.8 row: Error rides Required sessions as ciphertext (connect-2).

Changes: §6.5.

Questions: `plan-PROTO-version-error-range.md`.

### QD-479: No section says who owns topic `mail`'s sequence
*Proposed fill: a gap the agents filled; work builds on it. Also amends §14, §15.*

`mail` is a clock version, with no durable sequence: the writer's clock in ms, per client, raised past the stored value by HINCRBY as `gkm`'s is, so mxedge, smtpedge and api may all write it. §6.8's registry row reads `mail §14, §15 the writer's clock in ms, per client`.

Changes: §6.8 topic registry.

Questions: `plan-MAIL-hints.md#3`.

### QD-515: ComponentQueueMessageCount
*Proposed fill: a gap the agents filled; work builds on it.*

256 envelopes, four of §6.6's 64-message peer queues.

Questions: `core-types-open-default-numbers.md#4`.

### QD-527: Row (a): GroupForm's message, purpose and SignedType
*Proposed fill: a gap the agents filled; work builds on it.*

GroupForm stands as landed in protocol/gkm.proto: repo_id = 1, group_id = 2, previous_group_id = 3, generation = 4. Purpose group-form; SIGNED_GROUP_FORM = 0x1305 in signed.proto, after SIGNED_DELEGATION_WRAP. §6.9's purpose list and §6.11's 0x13xx comment add it. The signer is Signed's.

Changes: §6.9 purposes; §6.11 SignedType comment.

Questions: `plan-KEYS-wire-gaps.md#1`.

### QD-576: Autogroup atoms
*Settled by the agents from the design; work builds on it.*

[protos-bridge-unwritten-numbers#7] ACL_AUTOGROUP_DST_OWNER is 14, and a *_atoms field holds an autogroup as 16 bytes: fifteen zeros, then the enum value. Tag and group atoms stay with plan-ACL-atom-and-rule-ids. [plan-ACL-atom-and-rule-ids#2] In a *_atoms field an autogroup is 16 bytes: fifteen zero bytes, then its AclAutogroup value, 1 to 14. autogroup:dst-owner is 14. No tag or group id takes that form.

Questions: `protos-bridge-unwritten-numbers.md#7`, `plan-ACL-atom-and-rule-ids.md#2`.

### QD-583: Which milestone ends relay-only for same-network pairs
*Settled by the agents from the design; work builds on it.*

M6. PROTO-M6-02 stays there. It is neither Later nor M10.

Questions: `plan-PROTO-p2p-milestone.md#1`.

### QD-595: Messages left out of this track, each waiting on the task that owns it
*Settled by the agents from the design; work builds on it.*

No action in this file. Each stays with its owner: MailHint and MailDeposit with MAIL-M7-01 (plan-MAIL-format-bytes, plan-MAIL-hints, plan-MAIL-deposit-shape); SmtpOutcome and SmtpStatus with SMTP-M9-01 (plan-SMTP-wire-gaps); TlsHint with TLS-M5-05 (plan-TLS-small-readings); CoreHint with plan-CORE-core-hint-body; DnsZoneChanged with DNS-M5-09, which gives it no fields; gkm's stored bodies with plan-KEYS-wire-gaps row f; evs's stored objects and request bodies with plan-EVS1-format-bytes.

Questions: `protos-services-unwritten-numbers.md#7`.

<a id="s7"></a>
## §7 Networks, teams, members, enrollment, and SSO

### QD-001: A hacked server can replay revoked grants under new ids
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §10, §16.*

[protos-bridge-statement-id-wrapper] The statement id, proposal_id, delegation_id, SidecarRow.admission_sha256 and UrMlsCredential.admission_sha256 of a SidecarAdmit are bridge.SignedBytesSha256(purpose, type, body). The ring keeps the first 16 bytes of that hash for statements a reader applied, so a copy it refused burns no id, and a retry under another wrapper returns its entry. A_0 and genesis_sha256, C_v and §16's hashes stay as they are: they are pinned or chained, never checked for a repeat, so another wrapper there fails closed. [team-records-admission-sha256-under-proposal] One rule for both paths: `admission_sha256` is `bridge.SignedBytesSha256(purpose, type, body)` over the SidecarAdmit body, taken from `Signed.body` or from `AuthorityProposal.statement`. The first device's credential names `genesis_sha256`. TEAM-M2-03's row for a k-of-n or recovery admission and the check of `UrMlsCredential.admission_sha256` use it.

Changes: §7.9 statement, replay, proposal and retain rows; §10.4; §10.5; D-TEAM-20; §7.9; §10.4.

Questions: `protos-bridge-statement-id-wrapper.md`, `team-records-admission-sha256-under-proposal.md`.

### QD-005: No section gives the bytes of a statement's sealed body
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §8, §10, §17.*

One format for every `sealed_body`, `sealed_services` and `sealed_rules` field, which stay `bytes`: u64be(g) || nonce (24 random B) || XChaCha20-Poly1305(K, nonce, pt, aad). K = HKDF-SHA256(RK_g, salt repo_id, info "UR evs 1.0 statement" || u64be(g)), 32 B, adding `statement` to §10.5's purposes; repo_id is the config repo's, or for an owner-bound repo's RepoVersioning rules that repo's own. aad = "urnetwork-sidecar-v1/sealed-body" || 0x00 || u32be(SignedType) || header.network_id || header.nonce || u64be(g). pt = the *Body message, deterministically encoded, then 0x80, then zeros to a multiple of 256 B. A reader that holds RK_g opens it. One that lacks g keeps the entry pending and applies its id-level effect, opening it once RK_g arrives. If AEAD or padding fails, the id-level effect stands, the sealed effect is void and the reader alarms. api and keyless device roles never open one. RecoveryRebind{reason: compromise} is a revocation for §7.9's `check` row, so the witness stop does not hold it. Helpers: `SealConfigBody` and `OpenConfigBody` in sidecar/config_seal.go, with testHookSecret at K.

Changes: §7.9 Indexers; §7.9 RecoveryBind; §8.8 RepoVersioning; §10.5; §17.8.

Questions: `plan-TEAM-sealed-field-format.md`.

### QD-019: Whether per-run cost totals reach the team record, where admins can read a per-person series
*Decided by the owner: owner 2026-11-06.*

per-run totals (tokens by model and reported amounts, never a model_call) go to the team record by default, with Proposed's grouping rules: `ur record cost` groups by project, client or month, never ranks people, and folds groups under 5 members into other. A Team turns it off with ServiceSettings.record_cost, signed by an Owner or Admin, and every member's `ur status` names the setting. This replaces Proposed's off-by-default. (The recommendation it replaces: Per-run totals (tokens by model, reported amounts) go to the team record only in a Team that turns them on: `ServiceSettings.record_cost` (field 8, since `mail_strict` keeps 7, off by default, signed by an Owner or Admin), named in every member's `ur status`. Never a model_call. `ur record cost` groups by project, client or month, never ranks people, and shows groups under 5 members as `other`, which shapes the tool and is no privacy control. Counsel reviews before RS2, and also says whether the default may flip.)

Changes: §7.9 ServiceSettings; RECORD.md sections 6.3 and 13.1; Q-RECORD-6.

Questions: `record-md-run-cost-in-team-record.md`.

### QD-050: Who files the team record's RepoCreate, what refuses a second, and whether a Team may go without one
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §8, §11.*

`team-create`'s first Owner device files RepoCreate{kind team_record} right after the directory's, and an admin device that finds a team whose access logs hold no team_record RepoCreate files it. api and readers refuse a second live one in a network, and api one outside the team tier. Its admins are its creator and every config writer, as the directory's. A RepoDelete of it stands: only a person's /dev/tty-confirmed admin command files a new one, so a Team may decline the ledger and route as personal (RECORD.md section 4.2).

Changes: D-TEAM-28; §7.5; §8.8 RepoCreate row and directory paragraph; §11.12; Q-RECORD-3.

Questions: `record-md-team-record-creation.md`.

### QD-059: Stored rows lack fields the published list shows
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

[protos-bridge-row-fields#1] Add to SidecarRow: bytes identity_public_key = 16; string identity_alg = 17; bytes member_id = 18; repeated bytes tag_ids = 19; bool ephemeral = 20. §7.9's comment lists them. About 80 B a sidecar, so 5,000 admissions cost about 400 KB inside the 4 MiB bound. [protos-bridge-row-fields#2] Add to DelegationRow: bytes pubkey = 9; bytes reader_xwing_public_key = 10; uint32 max_admits = 11. §7.9's comment lists them. [protos-bridge-row-fields#3] Reserve ProjectionRows field 6 at M2 as repeated TeamScopeRow team_scopes, and define TeamScopeRow{label, member_id or tag atom} at M6 with Team scopes. Format-1 readers skip it.

Changes: §7.9.

Questions: `protos-bridge-row-fields.md#1`, `protos-bridge-row-fields.md#2`, `protos-bridge-row-fields.md#3`.

### QD-062: Tag and group ids name a key that does not exist
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §8, §2, §16, §17.*

[g0-density-keyed-tag-ids] Atom ids are random and table-held, with no key. A tag or group's atom_id is 16 bytes of crypto/rand, drawn by the writer the first time a head names it, redrawn if its first 15 bytes are all zero (acl.proto keeps that form for autogroups), and kept beside its name in the config's sealed `tags` or `groups` file for as long as the name lives. compile reads it from there and refuses a name with no row, so compile stays a pure function of the head. Signed tag_ids stay valid because an id never changes, and a tag deleted and made again gets a new id, so old admissions do not regain it. "keyed HMACs", "keyed ids" and "keyed tag ids" become "opaque ids" in §7.9, §8.7, §8.8, §2.8 api-7, §16.11, §17.8 and Q-ACL-8. This is plan-ACL-atom-and-rule-ids.md#1's answer. [plan-ACL-atom-and-rule-ids#1] Make atom ids random and table-held, with no key. A tag or group's atom_id is 16 bytes of crypto/rand, drawn by the writer the first time a head names it, redrawn if its first 15 bytes are all zero (acl.proto keeps that form for autogroups). It lives beside its name in the sealed `tags` or `groups` file for as long as the name does. compile reads it from there and refuses a name with no row, so compile stays a pure function of the head. Signed tag_ids stay valid because the id never changes, and a tag deleted and made again gets a new id, so old admissions do not regain it. Wording: "keyed HMACs" and "keyed tag ids" become "opaque ids" in §7.9, §8.8, §2.8 api-7, §16.11, §17.8 and Q-ACL-8.

Changes: §7.9; §8.7; §8.8; §2.8 api-7; §16.11; §17.8; Q-ACL-8; §7.9 Writes.

Questions: `g0-density-keyed-tag-ids.md`, `plan-ACL-atom-and-rule-ids.md#1`.

### QD-068: A service token must name its network
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

§7.8's access token gains network_id, the claim name its ID token already uses, minted by the exchange from the subject client's network. TEAM-M1-06 adds it, OPS-M1-04 maps it to Principal.NetworkId, and Principal.Validate keeps refusing a token without it. Registered claims (iss, iat, exp, jti) stand beside the list.

Changes: §7.8.

Questions: `core-types-token-network-claim.md`.

### QD-070: A dropped depositor keeps writing until its token ends
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §8, §10, §16, §11.*

[g0-recheck-0-deposit-scope#1] Option 1, as one rule for all four scopes. §7.9's tokens row reads: evs and gkm honor a capability for R only while its subject holds that right on R in their newest verified state, besides rev/ objects: r while it reads R, rw and admin while it writes R, deposit while §8 gives it deposit on R or it reads an owner-bound R it does not write (§16.8's receipts), by a cached per-repo bitset of those three rights. D-ACL-21, §8.10's evs row, §8.12 and §10.6's opening say the same and name deposit; §11.8 stands as written. The deposit bit is computed as the exchange computes its deposit scope: EvsAccess(deposit) with §8.6's ceiling and hardDeny, plus the §16.8 receipt case. gkm's drop-key route takes the same HonorScope call rather than an exception, though the key it serves is public. FS-23 adds: a deposit grant revoked or expired, the sidecar still admitted, is refused at evs within §8.9's 5 s. Settled against the question's closing remark and plan-ACL-small-readings#11: the drop-key route takes this check too. [plan-ACL-small-readings#11] As g0-recheck-0-deposit-scope#1: evs and gkm honor `deposit` only while its subject may deposit in their newest verified state, a third bit per subject in §7.9's cached set, gkm's drop-key route included through the same HonorScope call. D-ACL-21, §7.9's tokens row, §8.10 and §8.12 name deposit beside r, rw and admin, and §11.8 stands.

Changes: D-ACL-21; §7.9 tokens row; §8.10 evs row; §8.12; §10.6 opening; FS-23; §7.9 tokens; §8.10.

Questions: `g0-recheck-0-deposit-scope.md#1`, `plan-ACL-small-readings.md#11`.

### QD-071: No object holds the Signed Genesis, and entry 1 is pruned
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

Option 1, with the write order fixed. (1) `proj/<network_id>/00000000000000000000/_` holds the Signed Genesis bytes verbatim, not an AuthEntry, written If-None-Match and kept for the network's life; retention never deletes n = 0. (2) `POST /network/config/projection` gains `genesis`, required only at version 1. api checks SHA-256(genesis) = prev_chain and §7.9's `who`, then PUTs projrows, entry 1 (If-None-Match, still the race's commit point) and entry 0, and a retry of base 1 repeats a missing step. (3) `GET /network/config/projection?after=0` returns `genesis` beside the entries, unadmitted clients included, and answers 503 while entry 1 exists without entry 0. (4) `sha256(Genesis)`, AuthKeyBundle's and Pending's `genesis_sha256` and an invite's hash all mean SHA-256(Signed Genesis) = A_0. (5) The first head holds the same bytes at `genesis`, and after a site loss `POST /network/config/reseed` takes them from devices under §7.9's two-member rule. (6) §2.8 api-7 adds the Signed Genesis, kept for the network's life (I-18).

Changes: §7.9 Bootstrap; §7.9 base; §7.9 retain; §7.9 retention; §7.9 site loss; §7.17 API routes; §2.8 api-7.

Questions: `plan-TEAM-genesis-custody.md`.

### QD-072: No signed fact proves §8.5's `invited` clause
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §8, §2.*

Add `SIDECAR_CAPABILITY_INVITED = 4` (bit 2) to auth.proto's SidecarCapability. The admitting device sets it only after the invite's join MAC verifies (§7.5), a JIT member's first device included, from the invite that device issued (§7.6). §8.5's clause reads: d's SidecarAdmit carries the bit, and d is the first admission under M in log order, revoked ones included, that is neither ephemeral nor read_only. A later device's bit counts for nothing, and readers ignore it on an ephemeral or read_only admission. Rows carry it in SidecarRow.capabilities, so §2.8 api-7 needs no new row.

Changes: §7.9 SidecarAdmit; §8.5; D-ACL-22.

Questions: `plan-ACL-invited-consent-evidence.md`.

### QD-081: api cannot read or open a config head, so §7.9's descent check must work from pushes the writer hands it
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §11, §19.*

api never reads the config repo. It judges descent only, from Signed EvsPush statements the writer supplies; records, signer roles and compile stay with readers. (1) `config_head_sha256` is C_v of the config repo's `main` ref at `config_version` (§11.8). (2) `POST /network/config/projection` gains `config_pushes`: the Signed EvsPush of each version in (previous base's config_version, config_version], oldest first, at most 4,096; empty when the version is unchanged, and then config_head_sha256 must equal the previous base's. (3) api walks forward from the previous base's config_head_sha256, for base 1 from C_0 = SHA-256("UR evs 1.0 ref" || repo_id || ref_id) with Genesis's config_repo_id: each push names that repo, its base_version and base_chain equal the running (v, C), and C_v = SHA-256(C_{v-1} || push_id_v || SHA-256(Signed EvsPush_v)). A mismatch answers 403. The pushes are not stored, so the log's bytes do not change. (4) The first head's EvsPush is signed before base 1, so it carries auth {0, A_0}: A_1 hashes that head's C_1, and a pin of A_1 would be circular. evs takes that pin only on a config repo's first push. (5) Site loss: `POST /network/config/reseed` takes the same statements from version 1 to the re-seeded head, and api discards the adopted run unless the newest adopted base's (config_version, config_head_sha256) lies on that walk from C_0. (6) §7.9's Writes says readers replay records and api checks this chain. §19.4 does not change.

Changes: §7.9 Writes; §7.9 base; §7.9 Bootstrap; §7.9 site loss; §7.17 API routes; §11.8; §19.10.

Questions: `plan-TEAM-api-config-head-reach.md`.

### QD-086: Where a KeyRegister carries the new key's own signature
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §16, §6, §2, §10.*

Add to KeyRegister, set only for purpose presence and written last: bytes key_signature = 9; WebAuthnEvidence key_webauthn = 10. The new key signs the received body bytes before field 9, as UrMlsCredential signs fields 1-7 with its signature last (§10.4): a verifier slices at field 9's first byte, never re-marshals or empties a field, and refuses a body where anything follows fields 9 and 10. The signed bytes are §6.9's with purpose key-proof and type SIGNED_KEY_REGISTER; webauthn-es256 takes that hash as its challenge with UP and UV set and evidence in key_webauthn, and ecdsa-p256-sha256 a DER signature in key_signature. The identity key's Signed covers the whole body, and any countersignature stays in Signed.webauthn. api-7 gains a key registration's proof.

Changes: §7.9; §16.6; §6.9; §2.8 api-7.

Questions: `protos-bridge-presence-gaps.md#3`.

### QD-117: What zero team_mail means
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §15.*

§7.9 writes team_mail: indexers | member scopes (indexers), and TEAM_MAIL_MODE_UNSPECIFIED reads as indexers. A tag:mail device still needs an IndexerSet for mail before it registers (D-MAIL-15), and member scopes stays an explicit choice that turns {mxr_}'s scope routes on.

Changes: §7.9; §15.5.

Questions: `protos-bridge-team-mail-default.md`.

### QD-129: Is ur.io's OAuth consent page in scope, given owner rule 6?
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Recommend in scope: change mmm/ur.io/react/src/components/OauthConsent.jsx on mmm's `sidecar` branch to show the matching code and the one command from `authorization_details`, and add one line to HANDOFF section 5's mmm row. It is the issuer's `authorization_endpoint` and a security control, not product UI.

Changes: HANDOFF section 5; owner rule 6 (its reach).

Questions: `plan-TEAM-consent-page.md`.

### QD-139: Who can require fail-closed hooks for a Team, and how a member's ur learns it
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §16.*

Recommended: `ServiceSettings.record_required`, bool, false by default, config.proto field 9, reserved at M2 and read from M6, set by an owner or admin and never through MCP. Field 9, since `mail_strict` (plan-MAIL-strict-setting) keeps 7 and `record_cost` (record-md-run-cost-in-team-record) takes 8. While it is set, `ur install-harness` writes `onFailure: block` (Claude Code) and `failClosed: true` (Cursor) on every `ur hook` entry, adds `--required` to the hook command and seals that form. `ur hook --required` exits 2 when the daemon cannot take the event, because §16.7's hook exits 0 and neither setting would otherwise ever fire. The config-hash check counts a fail-open form as a changed config, so such a run taints, and `ur status` names each fail-closed harness. Codex documents no fail-closed setting, so there `--required`'s exit 2 blocks a PreToolUse only while the hook runs, and `ur status` says so. Enforcement stops at a member's own daemon: a same-uid edit taints but cannot be prevented.

Changes: §7.9 ServiceSettings; §16.7 How; §16.7 harness table.

Questions: `plan-MCP-record-required.md`.

### QD-171: compile must be pure, yet user:, network: and client: resolve through server data
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §8, §12.*

Option 1 with its sources fixed. A sealed config file `resolve` holds ConfigResolution{members: [{email, member_id}], networks: [{text, network_id}], clients: [{client_id, sidecar_id}]}, one row per selector the policy names and no others, so it adds no email beyond §7.9's "the emails it names". compile reads only it and refuses a selector with no row. The writer fills it at save, and a server answer is only a proposal, as §7.6 treats SCIM: email: the writer's own invite record where it has one, else `GET /network/members`; the preview lists each new or changed row with the member's role and devices, and the person's confirmed save signs it. network: §12's ResolveNetworkLabel, label or alias, never a legacy name (D-DNS-2), the id pinned until a person saves again, so a moved alias retargets nothing (§7.12). client: a dual-signed SidecarIdentityBinding the writer verifies itself (plan-CORE-client-to-sidecar-lookup); a client with no binding stays a literal client id (plan-ACL-nonsidecar-subjects). Validation refuses a member_id with no live MemberRow, so a stale row fails closed until the next save. §8.4's grammar and the stored source do not change.

Changes: §7.9 Repo; §8.8 Saving; §8.18.

Questions: `plan-ACL-selector-resolution.md`.

### QD-174: The list of records that enter the log is short
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

[plan-TEAM-config-head-format#2] Every record that opens with a StatementHeader enters the log at once through `POST /network/config/delta`, as protocol/descriptor_test.go's TestStatementsOpenWithHeader lists them. §7.9's Writes list therefore gains MemberAdmit, Delegation, an admin's SidecarAdmit and AdminSet. AdminSet rides an AuthorityProposal at k > 1 and files alone at k = 1 (§7.9's `k = 1` row), so the question's "always" is wrong. ServiceSettings, VersioningRules and BridgeBlock carry no header, ride heads only and take effect at the base naming the head, as do the config files (policy, tags, groups, names, labels, K_sock, BridgeShareSigners). The cascade's "the base whose config head first holds it" covers those. §2.8 api-7's statement list gains MemberAdmit, Delegation and unscoped SidecarAdmit, whose contents rows already show. [protos-bridge-unwritten-numbers#2] No header on Genesis, ProjectionHeader, ServiceSettings, VersioningRules and BridgeBlock. Every other record, MemberAdmit and Delegation included, carries one and enters the log, as plan-TEAM-config-head-format's item 2 rules.

Changes: §7.9 Writes; §2.8 api-7.

Questions: `protos-bridge-unwritten-numbers.md#2`, `plan-TEAM-config-head-format.md#2`.

### QD-204: `mail.strict` is named as the config's signed setting and exists in no record
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §15.*

Add `bool mail_strict = 7` to `ServiceSettings` in §7.9 and protocol/config.proto, signed by an owner or admin, network-wide, default false, reserved before M2's freeze as `directory` was (D-PHASE-9). §15.4's `mail.strict` and `MailAuthEvidence.strict_chain`'s comment name this field. Older readers ignore it and never claim `strict_custom_mx`.

Changes: §7.9 ServiceSettings; §15.4.

Questions: `plan-MAIL-strict-setting.md`.

### QD-227: A page Worker cannot HeadCheck, though §7.9, §18.8 and §22.7 say it does
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §18, §22.*

A page Worker runs no HeadCheck until C4 (Later): it neither witnesses nor is witnessed, raises no `unwitnessed` alarm, seals nothing, and shows no `witnessed_at`. It keeps its digests and newest 64 KiB per §7.9's `retain` row, but it uploads nothing: §7.9's `upload` row and §7.17 refuse read_only devices at `POST /network/config/reseed`, so the filed reading's 'uploaded over HTTPS' is dropped. design-records marks 'HeadCheck replies' in §7.9's read_only row and §18.8's Identity bullet as from C4, moves §22.7's 'its HeadCheck counts as a witness' (FS-106) to C4, adds to §18.8's `disclosed` row that a page's view is unwitnessed until then, and scopes I-16's witness clause accordingly.

Changes: §7.9 read_only row; §18.8; §22.7; FS-106; I-16.

Questions: `plan-SDK-small-readings.md#8`.

### QD-245: acl_subject_client_id belongs on network_client; §7.7's owner-row list is wrong
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §19.*

Delete `acl_subject_client_id` from §7.7's `network_client_owner` list. It is the nullable column `network_client.acl_subject_client_id`, added in MG2 (§19.7), never in MG0. M1's enrollment writes no subject: NULL reads as itself for a top-level client, else as its source client's subject (D-ACL-3). From MG2 the mint writes it once at creation, which is what §7.8's Enrollment bullet means.

Changes: §7.7.

Questions: `plan-TEAM-acl-subject-column.md`.

### QD-250: "The tier its token declares" cannot work
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §21.*

§7.10's `cleanup` row reads "from 90% of the network's `config_admissions`, from `GET /sidecar/limits`", in place of "the tier its token declares". An admin's device reads that value, which also sees §21.7's rows.

Changes: §7.10; D-TEAM-29.

Questions: `plan-QUOTA-small-readings.md#9`.

### QD-628: Should AuthLog.tla hold a recovery-signed proposal pending at its k-th device cosign, as §7.9 does, rather than completing it there?
*Decided by the owner on 2026-11-10, asked one question at a time.*

AuthLog.tla holds a recovery-signed proposal pending at its k-th device cosign, as §7.9 and TEAM-M2-05's code do: in TypeRule's cosign case a proposal of kind recovery returns 1 and its completion is left to the tick, and rcosign joins the design's alphabet. The design-details track reruns the four design configurations and records their new state counts in DESIGN-DETAILS.md 5.3. Nothing in the code waits on it.

Changes: sidecartest/model/details/AuthLog.tla and DESIGN-DETAILS.md 5.3 (design agent).

Questions: `details-5-model-recovery-cosign.md`.

### QD-646: Where does §7.10's cleanup list get each listed page Worker's admission time, when rows carry only its admission position?
*Decided by the owner on 2026-11-10, asked one question at a time. Also amends §2.*

SidecarRow gains int64 admitted_time_ms (field 23), set at apply from the entry where the admission takes effect (the admitting entry's, completing cosign's or tick's time_ms), carried through bases like admitted_at, computed by every reader including rows-only gates so rows stay equal, and listed by CleanupList beside the position. About 11 B per admission in rows; §2.8's api-7 text changes with no new exposure (design-records). TEAM follow-up: the field, its apply and carry, CleanupList, and CORE-M6-04's display.

Changes: TEAM follow-up: SidecarRow.admitted_time_ms = 23, apply and carry, CleanupList; CORE-M6-04 shows it; §7.9 rows and §2.8 api-7 text (design-records).

Questions: `team-m4-01-cleanup-admission-time.md`.

### QD-647: Does a forwarding Delegation owe Owners and Admins the network authority notice that every new Delegation owes today?
*Decided by the owner on 2026-11-10, asked one question at a time.*

A forwarding Delegation owes Owners and Admins no network authority notice: server/model/config_log_effects.go's configLogEntryEffect counts only Delegations without forward_sidecar_id. R-TEAM-12's 'new credential paths' and §7.8's Notices line read as paths that can admit devices or sign people in, as security_notice_authority.go already words it (design-records). The device's own admission already carried its notice. A one-line TEAM follow-up with its test.

Changes: TEAM follow-up: configLogEntryEffect skips forwarding Delegations, with a test; §7.8 Notices line and R-TEAM-12 wording (design-records).

Questions: `team-m2-20-forwarding-delegation-notice.md`.

### QD-648: When does a superseded or ended forwarding Delegation's row leave ProjectionRows, since it has no not_after and every app device files a new one at least each 90 days?
*Decided by the owner on 2026-11-10, asked one question at a time.*

A superseded or ended forwarding Delegation's DelegationRow leaves ProjectionRows at the first base whose retention point passes the later of its superseded_at and ended_at by 4,096 positions: one rule in the base compile, a function of rows and positions alone, so every reader drops it alike (DESIGN-DETAILS 5.2.3). Past that point §7.9's replay row already refuses its Signed bytes, and nothing admits under a non-live forwarding key. A DelegationRevoke naming a dropped id is refused as unknown. KEYS-M8-01's holder set reads only live rows. TEAM follow-up in sidecar/config_forwarding.go and the base compile; §7.9's rows text (design-records). Whether an ended auth key's Delegation row should also leave past its not_after is left for later, as small and not urgent.

Changes: TEAM follow-up: the base compile drops superseded or ended forwarding rows past retention + 4,096 (config_forwarding.go, config_base.go, tests); §7.9 forwarding and replay rows (design-records).

Questions: `team-m2-20-forwarding-rows-accumulate.md`.

### QD-287: The sealed split of statements
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §17.*

Keep the split as landed: each statement shows only what api-7 lists, and a sealed_body (sealed_services, sealed_rules) opens to a *Body message, for IndexerSet, RecoveryBind, RecoveryRebind, RepoVersioning and every §17.8 delta but BridgeWithdraw. BridgeAlias shows only its header. The seal's bytes stay with plan-TEAM-sealed-field-format, and BridgeEgress's mode with plan-BRIDGE-egress-mode-at-gates.

Changes: §7.9; §17.8.

Questions: `protos-bridge-unwritten-numbers.md#5`.

### QD-451: Field numbers of records written as lists
*Proposed fill: a gap the agents filled; work builds on it. Also amends §8, §17.*

Ratify as landed: numbers follow the order the text writes, StatementHeader at field 1. design-records writes them as fenced blocks in §7.9, §8.8 and §17.8, and TEAM-M2-01 and ACL-M2-01 check them line by line.

Changes: §7.9; §8.8; §17.8.

Questions: `protos-bridge-unwritten-numbers.md#1`.

### QD-456: The config repo's paths and the fold record format
*Proposed fill: a gap the agents filled; work builds on it.*

Option 2, sharded. On the config repo's file-mode `main` ref: `genesis` (Signed Genesis, verbatim, first head only); `fold/<d>/<i>`, the i-th fold, i from 1 and d = i / 1024, each zero-padded to 8 digits, one file per head that advances folded_through; `service_settings`, `versioning_rules`, `bridge/block`, each one Signed record verbatim; `bridge/share/<share_id hex>`, a BridgeShareSigner; `socket/key` (plan-SOCK-ksock-rotation); `policy.hujson`, the source bytes; `tags`, `groups`, `rules`, `names`, `labels`, `resolve`, one deterministically encoded protobuf each. config.proto adds `message ConfigRecord { bytes id = 1; uint64 n = 2; int64 time_ms = 3; uint32 kind = 4; bytes body = 5; }` and `message ConfigFold { uint64 after = 1; uint64 folded_through = 2; repeated ConfigRecord records = 3; }`. id is SHA-256(Signed) for a STATEMENT and empty for a TICK; n and time_ms are the carrying entry's; kind is AuthEntry.kind, 2 or 3; body is AuthEntry.body verbatim; records run in n order with no BASE. §7.9's BASE check reads the fold files whose ranges lie in (previous folded_through, folded_through].

Changes: §7.9.

Questions: `plan-TEAM-config-head-format.md#1`.

### QD-497: Enum values for named lists
*Proposed fill: a gap the agents filled; work builds on it. Also amends §8, §11.*

Ratify as landed: 0 is UNSPECIFIED, then written order: MemberRole (§7.5), RepoKind (§11.12), AclAction and AclAutogroup (§8.4), and each a | b choice. SIDECAR_CAPABILITY_READ_ONLY is 2.

Changes: §7.5; §7.9; §8.4; §11.12.

Questions: `protos-bridge-unwritten-numbers.md#3`.

### QD-498: Field types the text leaves open
*Proposed fill: a gap the agents filled; work builds on it. Also amends §17.*

not_after, expires and drain_until are int64 ms since the epoch under the design's names. An IPv4 prefix is BridgeIpv4Prefix{fixed32 address, uint32 length}. AuthorityProposal.statement is the proposed type's whole body as signed, and only the proposal's own header is judged for replay and expiry.

Changes: §7.9; §17.8.

Questions: `protos-bridge-unwritten-numbers.md#6`.

<a id="s8"></a>
## §8 Access control

### QD-044: In M's owner-bound repo, may M's device undo an admin's standing revoke, and can an admin revoke M's own device there?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §22.*

Recommend option 1. In an owner-bound repo, a later EvsShare to that subject from a consented device of the owner lifts a config writer's standing RepoRevoke, and the fold drops the row from AclRepo.revokes at that position. A RepoRevoke naming one of the owner's consented devices is refused, since SidecarRevoke and Suspend already remove a device.

Changes: §8.8 RepoRevoke; §8.5; §22.5.

Questions: `plan-ACL-owner-bound-standing-revoke.md`.

### QD-055: Services with no database have no way to read rules or quotas
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §19, §2, §20.*

[plan-SOCK-gate-data] Add one internal read surface on api under `/internal/gate/`, a prefix the lb refuses from outside, each caller holding its own bearer from `secret_files`, verified by hash, as plan-TLS-internal-credentials and plan-DNS-internal-route-credential settle: `GET /internal/gate/projection/<network_id>?after=<n>` (the newest base and the entries after n, as `AuthEntry` bytes), `GET /internal/gate/rows/<network_id>/<rows_sha256>`, `GET /internal/gate/listen-facts/<network_id>` (`network_verified`, whether a `mail_network` row exists, each `network_tls_cert` row's name and expiry), and `GET /internal/gate/over-limit` (spent and storage-over networks apart). Gates verify entries' chain and signatures as from `proj/` (§8.9), so api stays a carrier. Refresh: projection on `{acl_<networkId>}v` and the 5-min poll, facts at most every 60 s per network off the inline path, over-limit every 5 s. On failure the last verified projection, facts and list keep serving. A process that has never loaded them stays not ready, and a `tls/` entry with no cached facts answers `unavailable`. §8.9 states this once for every gate, §19.4 and §19.16 list the routes and credentials, and api-13's service list gains sockets. Other gates' reads join this prefix under the same rules (plan-QUOTA-host-reach, plan-SMTP-report-seal-key, plan-ABUSE-review-held-names#2). [plan-QUOTA-host-reach] One internal surface on api, the one plan-SOCK-gate-data's option 1 builds, each call on the per-service credential plan-TLS-internal-credentials settles: read a network's limits; read the over-limit list, spent networks apart; post a usage batch; read a payer's draw-ordered balances with credit; mark a network spent. All off the inline path and cached, per I-12. `CountRate` and reservations go straight to Redis through `ServiceHost.Redis`. `quotahost.NewApiQuota` serves evs, gkm, sockets, tlsedge and mxedge; api, connect and taskworker keep `NewLocalQuota`. In a Postgres outage batches retry and drop as §20.6 states, and the lists go stale. §19.4, §19.16 and §20.14 name the routes.

Changes: §8.9; §19.4; §19.16; §2.8 api-13; §20.14.

Questions: `plan-SOCK-gate-data.md`, `plan-QUOTA-host-reach.md`.

### QD-079: Folding the log drops suspensions and spent grants
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §16, §7, §9.*

[plan-ACL-folded-grant-state#1] AclRows gains `repeated AclSuspension suspensions = 8`, with AclSuspension{bytes subject = 1; bytes suspend_id = 2; uint32 signer_class = 3; bytes signer = 4; uint64 at = 5}, class 1 owner or sponsor, 2 admin, 3 k of n. A fold keeps a Suspend until an Unsuspend of its own suspend_id lands, and signer_class settles §8.8's rule for who may lift it. hardDeny, §7.9's leaves rule and BridgeIdentity.suspended read it. §2.8 api-7's rows add it (I-18). [plan-ACL-folded-grant-state#2] A GrantActivate folds to an AclRule: rule_id = grant_id (32 B), new `bytes source_rule_id = 10` = the CanonicalAction's rule_id, src the subject's derived atom, targets and actions from grant_dst and grant_allow, expires = expires_millis, and a publish's app_mode and link_spki_sha256. compile drops the rule once source_rule_id names no AclRequestRule in this head (FS-14) or a GrantRevoke names it. A `sock:` entry in grant_dst holds §9.4's token path in hex, never an application name, since GrantActivate shows api the action. That path dies at the next K_sock rotation, so such a grant ends there, the closed direction, and is requested again; plan-SOCK-ksock-rotation should say so in its overlap rule. [plan-ACL-folded-grant-state#3] AclRows gains `repeated AclSpentGrant spent_grants = 9`, with AclSpentGrant{bytes grant_id = 1; int64 retain_until_ms = 2}. Every activated or revoked grant_id enters it. retain_until_ms is the latest not_after_millis among its decisions plus 60,000 (§8.6's skew). A GrantRevoke of an id no activation carried has no decisions to read, so it keeps retain_until_ms = 0, meaning the network's life; readers can verify only an admin's such revoke, so these stay few. compile drops a row once retain_until_ms is below the newest ConfigRecord.time_ms in the head, never a clock. §8.8's `refuse` row reads: a grant_id in spent_grants, in an active rule, or in an entry after folded_through, or one a GrantRevoke names.

Changes: §8.8; §2.8 api-7; §16.8 grant_dst; §8.8 refuse.

Questions: `plan-ACL-folded-grant-state.md#1`, `plan-ACL-folded-grant-state.md#2`, `plan-ACL-folded-grant-state.md#3`.

### QD-080: No rule_id derivation, and hashing AclRule would move it at every K_sock rotation
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

A document rule's rule_id is 16 random bytes held in the sealed `rules` file, keyed by the SHA-256 of the rule's canonical form: RFC 8785 JCS of the parsed rule, lists sorted, `id` and `note` left out, socket names in clear. An unchanged rule keeps its id across saves and rotations. Any change of meaning makes a new id, so live grants under the old one end at that base (FS-14). Identical rules compile to one. compile refuses a rule with no row. An implicit-document rule takes the constant SHA-256("urnetwork-sidecar-v1/acl-implicit-rule" || 0x00 || u32be(index))[:16], with no table. An activated grant's rule_id is its grant_id. §8.5's `id` never enters rows (§8.7).

Changes: §8.8.

Questions: `plan-ACL-atom-and-rule-ids.md#3`.

### QD-092: §8.10 scopes the Public refusal to networks with a head row; §20.8 refuses every declared client
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §20.*

§20.8 wins. §8.10 takes "and Public ones from declared no-egress clients (§20.8)" out of the head-row Contract rule into its own sentence: CreateContract refuses them in any network, from M1. QUOTA-M1-04 refuses, and ACL-M4-01 calls the same check.

Changes: §8.10.

Questions: `plan-QUOTA-small-readings.md#14`.

### QD-102: A `general` repo's drop key, slots and deposit rights rest on an inbox status nothing records
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §15, §11.*

Option 1, widened to name the admin inbox. `RepoCreate{repo_id, kind, inbox}`: new `RepoInbox inbox = 4` in acl.proto and §8.8, 0 none, 1 group, 2 admin; valid only with kind general; 2 only from a config writer, once a network, and readers and api refuse a second. It lands with ACL-M2-06 before M2's freeze. Rotators set `drop_public_key` and `drop_not_after_ms` for a kind that takes deposits or when `inbox` is not 0 (KEYS-M2-20). Writers use §11.6's per-message slot rule for an inbox. `ur id group-create` files, beside the marker, `RepoGrant{role: deposit}` to `tag:mail` in a team network; an untagged receiver in a no-document network already reaches its deposit ref through the implicit document's `autogroup:member` write on `evs:*`. The marker is server-visible in the authorization log, so api-7's row adds it.

Changes: D-KEYS-17; §8.8 RepoCreate; §2.8 api-7; §15.7; §15.8.

Questions: `plan-MAIL-group-inbox.md`.

### QD-136: D-MAIL-8 needs one member's device to deposit into another's mailbox, which §8.5 and §8.8 do not allow
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §20.*

Option 1, narrowed. §8.5's `mailbox` deposit cell gains: any subject of the network that the projection marks `mail_send`. `vault` and `secret` stay as written, and §8.8's 'never in an owner-bound repo' stands. A member's device learns the mailbox from `mailcfg` and asks the token exchange for `repo:<id>:deposit`. §20's storage limits bound the harm, and the recipient's readers show 'from a member' by the push's signer (D-MAIL-8).

Changes: §8.5 kind defaults; §2.8 evs-6 (disclosure).

Questions: `plan-MAIL-member-deposit.md`.

### QD-170: Rows cannot express client:, legacy, role: or principal: subjects
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §22.*

Keep §8.4; rows name only what a writer can sign and never enumerate app clients. AclAtom gains `repeated bytes client_ids = 5`, `repeated bytes network_ids = 6`, `string role = 7` and `string principal = 8`; AclTarget gains `bytes client_id = 10`. A selector with no table name compiles to a derived atom, id = SHA-256("urnetwork-sidecar-v1/acl-atom" || 0x00 || kind || 0x00 || value)[:16], kind one byte (1 member, 2 sidecar, 3 client, 4 network, 5 role, 6 principal), unkeyed because each value is already server-visible. An app device with an owner row matches `user:`, `group:` and autogroups at the gate through `network_client_owner.member_id`, so app clients coming and going change no rows. A legacy client has no owner row and matches only `client:<id>`, `autogroup:untagged`, `autogroup:network` and `*`, and D-ACL-5's "naming it" is AclTarget.client_id under an unrestricted grant. `role:` and `principal:` match the identity getProvideRelationshipDetails's one query loads, never GetClientIdentity's Postgres fallback, so the gate stays under §22.5's DenyPostgresForTest. §2.8 api-7 adds these to atoms and targets (I-18).

Changes: §8.8; §8.10; §2.8 api-7.

Questions: `plan-ACL-nonsidecar-subjects.md`.

### QD-172: Rows carry no tagOwners, though api must verify a tag owner's scoped admission
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

AclAtom gains `repeated bytes tag_owner_member_ids = 4`: a tag atom's tagOwners, expanded to member_ids at compile. A tag atom's `member_ids` stays empty, and its `sidecar_ids` lists the sidecars carrying it. `CanApplyTag` reads field 4, and subject evaluation never does. §2.8 api-7 adds tag owners (I-18).

Changes: §8.8; §2.8 api-7.

Questions: `plan-ACL-atom-and-rule-ids.md#4`.

### QD-185: connect asks for a same-network reply as non-companion, so §8.10's rule refuses one-way grants' replies
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §6, §22.*

Leave connect alone. For a→b in a network with a head row, on the request's own `Companion` bit: (1) non-companion with reach(a,b): pass, class data. (2) non-companion without it but with reach(b,a): a reply. The gate returns that verdict from memory, then CreateContract runs `model.CompanionOriginExists` once, with the companion path's bounded origin wait, and an origin passes as class data. (3) Otherwise the witness exception gives class control, else NoPermission. (4) Companion: reach(b,a), as written. Step 2 must precede step 3, or a reply racing its origin sticks on a control contract. The gate's own decision stays under §22.5's DenyPostgresForTest; the origin read belongs to contract creation, runs only with a head row and only when reach(a,b) fails, and §22.5 says so. §6 states that sidecar RPC replies ride this rule. §8.3, §6.10.1 item 1, §6.11's citation of :912-927 and D-ACL-4 stop treating same-network replies as companions. §8.10 states the residual: while b's origin stands a holds a data contract to b, so a legacy b, which checks nothing, is reachable from a for that time, as under any reply path.

Changes: D-ACL-4; §8.3; §8.10; §6.10.1; §6.11; §22.5.

Questions: `plan-ACL-network-reply-contracts.md`.

### QD-212: Q-EVS-3's v1 prefix rules have no record, field or path syntax
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §11, §2, §7.*

Specify through design-records at M6's entry, on RepoVersioning's pattern: a new access-log statement RepoPrefixRules {repo_id, rules (sealed)}, signed by a repo admin or a config writer (owner-bound: a consented device of its owner), rules sealed to the repo's current generation, so api and evs see only that rules exist. A rule is {subject atom, path prefix in whole components, write}. Readers fold it at each push's auth pin, and a version no rule allows is ignored and raises evs_alarm prefix_rule. Reserve the statement's number before M2's Gn-in, since §7.9's records freeze there, and add api-7's clause (I-18).

Changes: §8.8; §11.22; D-ACL-11; §2.8 api-7.

Questions: `plan-EVS1-v1-unspecified.md#5`.

### QD-230: Who may file RepoCreate; the file's reading would break Team
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §7.*

The kind lets a member device, untagged, not ephemeral and not read_only, file RepoCreate of a general or record repo. A tagged or ephemeral sidecar may only under a rule giving it `admin` on `evs:*` or that repo, within §8.6's ceiling. team_record and mailcfg: a config writer, which no section names and these network-level repos need. Owner-bound kinds and directory stay as §8.8 says, config as §7.9's bootstrap. No `create` action is added, so a policy cannot stop a member creating repos.

Changes: §8.8 RepoCreate.

Questions: `plan-ACL-small-readings.md#4`.

### QD-265: §8.5's grant 1 lost its sidecars when D-ACL-20 narrowed autogroup:untagged
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

§8.5's grant 1 and `acl_team_start.hujson` read { "src": ["autogroup:member", "autogroup:untagged"], "dst": ["autogroup:self"], "allow": ["dial", "route"] }. FS-21's Team case uses peers of two members, since a member's own devices now reach each other.

Changes: §8.5.

Questions: `plan-ACL-team-grant1-src.md`.

### QD-266: M2 versus M4: when §8.8's statements are checked and folded
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §23.*

Every §8.8 statement, GrantActivate, GrantRevoke, Suspend and Unsuspend included, is checked and folded at M2. M4 adds the filing flows, the contract gate and closing of open contracts. §8.19 and §23.4's M4 row say so.

Changes: §8.19; §23.4.

Questions: `plan-ACL-small-readings.md#1`.

### QD-319: Grammar readings of §8.4 and §8.5 that ACL-M2-01 follows
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §9.*

Accept all twenty as landed in `ParseAclPolicy`; design-records states reading 1 in §8.4's note and reading 3 in §8.5. Reading 1: a last segment that is exactly `*` takes every name below its prefix. Reading 2: a bare `*` dst, `sock:*` and a first-segment glob reach application sockets and `share/` only, never `tls/`, `smtp/` or §9.4's other reserved first segments. Reading 7's nesting bound of 4 runs before `encoding/json`.

Changes: §8.4 note; §8.5.

Questions: `acl-policy-small-readings.md`.

### QD-359: Whether a `requests` rule may carry ports, audience, app mode, pin or expiry
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Keep `ip`, `via`, `sock`, `audience`, `app_mode`, `link_spki_sha256` and `expires` refused on a `requests` rule: a rule names who may ask and who answers, and the filed request names ports, audience and expiry. A Team narrows a rule through `dst`, `src` and `evidence`. Correct the ACL plan's "take a grant's fields" to match.

Questions: `acl-policy-request-rule-fields.md`.

### QD-367: What `GET /smtp/reports`' '§8 read' reads
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Read on the repo that holds the network mail key, by plan-SMTP-report-seal-key's rule: the same audience the sealed copy is sealed to.

Questions: `plan-SMTP-small-readings.md#16`.

### QD-392: autogroup:dst-owner for a socket means subjects holding `listen`
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A socket's listeners are the subjects holding `listen` on it in the state at the statement's position, never live registrations. One owner or sponsor across them names that one; otherwise autogroup:admin.

Questions: `plan-ACL-small-readings.md#5`.

### QD-396: `evidence` compiles to the effective list; naming harness stays local
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A rule with no `evidence` compiles AclRequestRule.evidence to `evidenceDefault`, else device, presence and harness. Whether the rule itself names harness stays in AclLocalPolicy, read only by the signing daemon's harness_ok. api and readers check d.channel against the row.

Questions: `plan-ACL-small-readings.md#7`.

### QD-397: `admin` implies write and read
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`admin` on a repo implies write and read of that repo, within §8.6's ceiling, and a read_only sidecar still gets only r. A policy grant of `admin` therefore adds a key holder, which the preview names as a reader.

Questions: `plan-ACL-small-readings.md#3`.

### QD-410: public_name keeps its glob
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

AclTarget.public_name keeps the glob text, such as `*-preview`, matched by §8.4's rule that `*` stays within a label or segment. "Finer globs project to their literal prefix" applies only to socket_tokens.

Questions: `plan-ACL-small-readings.md#10`.

### QD-530: §4 never chose a HuJSON parser
*Proposed fill: a gap the agents filled; work builds on it. Also amends §4, §22.*

In-repo. `aclStandardizeHujson` in sidecar/acl_hujson.go turns `//` and `/* */` comments and trailing commas into spaces, keeping byte offsets, refuses invalid UTF-8 and hands the result to encoding/json, on every leg. No new module and no dependencies.yml row. §22.6's compiler fuzz target covers it. A change to it counts as a format change, since every reader must parse one source alike.

Changes: §8.5.

Questions: `plan-ACL-hujson-parser.md`.

### QD-532: The K_sock config file's path and bytes
*Proposed fill: a gap the agents filled; work builds on it.*

Path `socket/key` in the config repo, a single-record file beside `policy.hujson`, which plan-TEAM-config-head-format's layout should list under this name. Bytes: `SocketKeyFile{bytes current_key = 1; bytes previous_key = 2; int64 rotated_at_ms = 3}` in protocol/config.proto, keys 32 B, `previous_key` and `rotated_at_ms` set from a rotation until the head that clears them. A config writer creates the file with the repo.

Changes: §8.8 Placement; protocol/config.proto.

Questions: `plan-SOCK-ksock-rotation.md#2`.

### QD-555: The change audit's command
*Proposed fill: a gap the agents filled; work builds on it.*

The config repo's signed head history is the change audit. Read-only `ur acl log` lists each head's config_version, signer and time, and never runs through MCP (D-MCP-17). A rollback is `ur acl push` of an older source, a new head at a higher version (D-ACL-9). Rename freely if cli/UI.md turns up (plan-CORE-cli-ui-missing).

Changes: §8.8; §8.17.

Questions: `plan-ACL-small-readings.md#13`.

### QD-561: CompileAcl's local output
*Proposed fill: a gap the agents filled; work builds on it.*

`CompileAclLocal(input *AclCompileInput) (*AclLocalPolicy, error)` runs on the same input as CompileAcl and holds what rows drop on purpose: exact socket globs, aliases, per-rule harness naming and names for previews. It is never serialized off the device. §8.17's Provides adds both names.

Changes: §8.17.

Questions: `plan-ACL-small-readings.md#12`.

### QD-589: Ephemeral sidecars and autogroup:member
*Settled by the agents from the design; work builds on it.*

An untagged ephemeral sidecar is in autogroup:member and takes reach from rules naming it, while §8.6's ceiling alone limits its evs access. A tagged ephemeral sidecar gets no deposit from the implicit autogroup:tagged rule, which does not name it.

Questions: `plan-ACL-small-readings.md#8`.

### QD-592: Policy tests run on the writer's device only
*Settled by the agents from the design; work builds on it.*

The writer's device runs `tests` before signing, and a failure blocks the head. Readers do not rerun them at replay.

Questions: `plan-ACL-small-readings.md#6`.

<a id="s9"></a>
## §9 Abstract socket listeners and the scheduler

### QD-109: §9.7's `est` filter holds a listener with 11 or more dialers to about `max_streams` new streams per report interval
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Step 1 of §9.7 filters on `reported_inflight` alone, and `est` stays for step 3's comparison, so `busy` means the listener said it is full. §9.7's Fairness bullet says so. `PickSocketListeners`' filter and `TestEnoughShortDialersFillEstWithAListenerNearlyIdle` change by one line each.

Changes: §9.7 step 1, Fairness bullet; §9.16.

Questions: `sock-pure-est-reach.md`.

### QD-122: During K_sock's overlap gates refuse every old token path, so the overlap protects nothing
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §8, §2.*

Keep the overlap at the gates. While the K_sock file holds a previous key, `CompileAcl` emits a second `AclTarget` under that key beside each `sock:` target, a pure function of head state, so gates' `MayListen` and `MayDial` need no change and readers recompile the same rows. A grant dropped by the rotating head drops on both paths. A requested grant's `sock:` entry is a literal token path (plan-ACL-folded-grant-state), so it gets no second path: it works while listeners register that path, through the overlap, and then its subject requests again. The first writer head at or after `rotated_at_ms` + 10 min clears the previous key. Listeners register both paths until `rotated_at_ms` + 10 min by their own clock, so sock-1's 10 min stays true even if no writer is online; a lister tries the previous key while the file holds it. api-7 then says rows hold both paths until that head, which links them for as long as those rows are kept, at least 30 days, not sock-1's 10 min.

Changes: §9.4; §8.8; §2.8 sock-1; §2.8 api-7.

Questions: `plan-SOCK-ksock-rotation.md`.

### QD-130: What adds and removes * and @ A and AAAA, and whether a network's edge use shows in DNS at all
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §12, §7, §21.*

Grant-driven, as §12.7 says. An edge grant is an active publish on dns:<host> in that zone, or the system publish: a network with a mail_network row and an approved smtp/25/mx listen grant, because mta-sts.<net>.<root> has no row of its own and resolves only through *. * has A and AAAA while the zone's set holds any host but @, or the system publish; @ has them while the set holds @. After each accepted POST /network/config/delta or /network/config/projection, once the object PUT has committed, api recomputes the set from S(n) and calls model.DnsSyncEdgeRecords, one journal write per transition and none otherwise. It is a separate transaction: §7.9 commits by conditional PUT, so the file's 'in the delta's transaction' does not exist. An hourly taskworker pass over §21.6's list reconciles both ways: it removes what expired and adds what a crash between the PUT and the write missed. Drop '(DNS)' from §9.4's FirstListen and LastUnlisten; they stay seams with no DNS consumer.

Changes: §9.4; §12.7; §12.14.

Questions: `plan-DNS-edge-record-trigger.md`.

### QD-190: A 2-hour DATA connection cannot live on a `ur/` stream that §9.6 ends at 60 minutes
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §6, §14.*

Option 1. Grant length becomes per `ur/` service, default 60 min. `ur/smtpedge`: `grant_expire_time_millis` = issue + 125 min and `{svc_}` TTL 125 min, 2 h plus 5 min for the ticket's 30 s, pre-TLS and `SmtpOutcome`. Contracts keep §6.10.1's rule and roll at their 60-minute deadline while the pair lives. The edge's own timers still end the connection at §14.4's 30 min, or 2 h in DATA mode, so the longer grant adds no longer session. SOCK-M9-01 holds the constant.

Changes: §9.6 SocketTicket and Edge Finds; §6.10.1 (unchanged rule, new TTL).

Questions: `plan-SMTP-data-connection-lifetime.md`.

### QD-241: `ur share add`'s default for an omitted --count
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Recommended: an omitted --count means uses = 1; --count=0 asks for unlimited until expiry and --count=n for n. State it in §9.9, and add that with uses = 0 only a Remove or expire_millis ends a share, since the end row's "a Done for each of uses Reserves" cannot fire.

Changes: §9.9; §9.16.

Questions: `g0-recheck-1-closed-item-text-errors.md#4`.

### QD-369: Whether ejection's 'reporters from 2 networks' stays literal, since it fires only for ur/ names
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Keep the rule literal: `SocketReportersEject` requires reporters whose `dialer_network_id`s differ, in one function. Ejection and `ejections_total` then act on `ur/` names only, and other namespaces rely on exclusion, the backup ticket and the 45 s lease. Change nothing else. Option 2 can be revisited if `tls/` measurements show a real cost, as it is one function.

Questions: `plan-SOCK-ejection-reporters.md`.

### QD-425: Front matter says `ur share` must run, where §9.9 says the sharing sidecar
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A share is served while the sharing sidecar runs. Change "while `ur share` runs" at asm/data_front6.py:159 and asm/data_registers6.py:199, add "and an expiry (24 h by default, at most 30 days)" to D-SOCK-16's register row at asm/data_registers6.py:70, and rebuild DESIGN.md.

Changes: front matter; Appendix A D-SOCK-16 summary.

Questions: `g0-recheck-1-closed-item-text-errors.md#3`.

<a id="s10"></a>
## §10 Group keys for evs: MLS and the GKM service

### QD-031: How long does a drop key live, that is, how long does a mailbox take mail with no reader online?
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Recommended: drop_not_after_ms = time_ms + 90 days, the setting GkmSettings.DropKeyLifetime, one value for every kind that takes deposits, together with row 2's renewal.

Changes: §10.5 GenRotate field 14; D-KEYS-8; D-KEYS-17.

Questions: `plan-KEYS-drop-key-lifetime.md#1`.

### QD-046: A forged reader key, beyond correcting the text
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §5.*

[g0-recheck-0-readerkey-forgery#2] Recommended: option 2 on top of the text fix, and no post-quantum signature. Once a day, at its ReaderKey upkeep, a device GETs /gkm/reader-key/<its own id> and compares the key digest with those it signed; a key it never signed raises SidecarEvent key_changed, a kind §5.4 lists and no section yet defines, naming the foreign digest, and the remedy is §10.5's for an active clone: SidecarRevoke{reason: compromise} and a new enrollment. ReaderKey keeps the three fields landed in protocol/gkm.proto. [g0-recheck-0-readerkey-forgery#1] Correct the text, option 1. §10.5's Ladder bullet says an adversary that can forge Ed25519 and that the operator serves "could forge admissions, or a holder's ReaderKey, to which an honest rotator or hinted holder then seals RK_g with no person acting, and, through the ladder, read all retained history". Its last sentence becomes: "An external commit needs RK_g, under which the GroupInfo is sealed, so a published identity key alone commits nothing; RK_g itself rests on those signatures." §2.18's unaudited-cryptography row adds "by a forged admission or ReaderKey", and the ledger's HNDL row replaces "Nothing" with this residual. Q-KEYS-2's residual stands.

Changes: §10.5 Ladder bullet; §2.18 unaudited-cryptography row; ledger row for R3's HNDL major; §10.5 readerkey row; §5.4 key_changed; §10.15 active clone row.

Questions: `g0-recheck-0-readerkey-forgery.md#1`, `g0-recheck-0-readerkey-forgery.md#2`.

### QD-057: New members cannot judge removal of a stale device
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §7, §5.*

[plan-KEYS-stale-remove-evidence] Not the question's option 1: give every member the same signed evidence. UrMlsCredential.not_after, field 6, today undefined, is ms since the epoch: the signing time plus 90 days, KeyPackages' life, and every UpdatePath leaf and external join re-signs the credential, so the tree carries each leaf's last change under its own identity key, and a Welcome joiner receives it. §10.9's Remove row: a stale Remove is valid iff the target's credential in the prior epoch's tree has not_after - 90 days + stale_leaf_days, read at the commit's auth pin, <= my clock + 60 s. Members judge this from the tree alone, so a one-day joiner and an old member agree. A writer leaf commits one only a day past that, and only if its own record shows no later change of that leaf. The value is evidence only: no commit is refused over it, and a leaf that inflates it delays only its own stale Remove. §7.10's "last change" and MemberDevice.LastChange read the same value. FS-97 adds: a Remove of a leaf inside the window refused by a member one day old. [plan-KEYS-wire-gaps#15] As plan-KEYS-stale-remove-evidence.md: ms since the epoch, the signing time plus 90 days, re-signed in every UpdatePath leaf and external join. It is evidence only, so no leaf already in a tree is refused over it.

Changes: §10.4 UrMlsCredential field 6; §10.9 Remove row; §7.10 stale and cleanup rows; §5.4 MemberDevice.LastChange; FS-97.

Questions: `plan-KEYS-stale-remove-evidence.md`, `plan-KEYS-wire-gaps.md#15`.

### QD-065: Nothing renews a drop key: a lapse closes no gate, and a returning writer may never write
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §6.*

§10.5's depositor row ends: "else it waits for a newer rotation, which the gate, or for a drop key with under 7 days left §10.6's renewal, makes writers write". §10.6 gains a duty row: a GET drop-key whose newest GenRotate has under 7 days to drop_not_after_ms hints pending to R's writers, at most once an hour per group and process; a writer on that hint, and every writer at its hourly resync (§6.8), rotates with cause SCHEDULE if its repo's kind takes deposits and the newest drop key has under 7 days left, with no write of its own. §10.9's rotation checks and the depositor rule add: time_ms < drop_not_after_ms <= time_ms + DropKeyLifetime + 10 min, as readerkey's check does, so no signer can void the backstop with a far-future value. KEYS-M7-01 adds: a returning writer renews with nothing to ingest.

Changes: §10.5 depositor row; §10.6 duties; §10.9 rotation checks; D-KEYS-17; FS-23.

Questions: `plan-KEYS-drop-key-lifetime.md#2`.

### QD-066: How does a ~6,000-delivery rotation fit §10.6's 5-minute gate target under W2's 1,200 gkm requests a minute?
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Option 1, at M2's entry, recovery wraps included. POST /gkm/groups/<id>/wraps/<g>/<c8> takes GkmWrapBatch{repeated bytes deliveries = 1}, 1 to 256 Signed ReaderWraps and DelegationWraps, and answers 200 with GkmWrapBatchReply{repeated GkmWrapResult results = 1}, GkmWrapResult{uint32 status = 1; bytes winner = 2}, in order: 201, 412 with the winner, 403, 409, 429, or 0 for not tried. New POST /gkm/groups/<id>/recovery-wraps/<g>/<c8> does the same for a rotator's RecoveryWraps, items {member_id, b8, ciphertext}; POST /gkm/recovery/<member_id>/wraps stays for a rebind. New POST /gkm/reader-keys {sidecar_ids, at most 256} answers each Signed ReaderKey or none, under the read row's scope. gkm runs each item through the wrap checks as today, 16 PUTs at once, starts no PUT past 20 s into the request, under the lb's 30 s, and marks the rest 0; If-None-Match makes a retry safe. §10.6's STAGED bound counts items. §10.5's step 3 reads "in batches of at most 256, up to 4 at once". A 6,000-object rotation is then about 45 requests, and W2 stands. KEYS-M6-03 adds a T3 case: a full rotation through the real lb limit.

Changes: §10.5 Rotate step 3; §10.6 wrap checks; §10.14 routes.

Questions: `plan-KEYS-wrap-route-rate.md`.

### QD-156: Row (h): no route reads GroupForms, and a depositor cannot learn its group id
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Add GET /gkm/repos/<id>/forms under r, rw and admin: the repo's Signed GroupForms, oldest first. Replace §10.14's GET /gkm/groups/<id>/drop-key?since=<g> with GET /gkm/repos/<id>/drop-key?since=<g>, scopes deposit, r, rw and admin, gkm resolving the newest GroupForm. D-KEYS-17's "only the drop-key route" stands.

Changes: §10.14 routes; §10.6 scopes.

Questions: `plan-KEYS-wire-gaps.md#8`.

### QD-165: Row (i): dropping GroupInfo from a generation-0 epoch object would wedge recovery
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Not the proposed text. A generation-0 epoch object still carries the sealed GroupInfo at 16 leaves or fewer and moves the pointer as any epoch does. It seals under K_groupinfo of the newest generation the self-joiner holds, named in GkmEpochObject.group_info_generation; GkmCommitHeader.generation stays 0 and it carries no GenWrap. KF5's "the generation it names" reads that field in every epoch object.

Changes: §10.6 GroupInfo row; §10.7 KF5.

Questions: `plan-KEYS-wire-gaps.md#9`.

### QD-177: `own`, `read` and D-KEYS-26 say any gkm token, while deposit reaches only the drop-key route
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

A token whose only repo scopes are deposit reaches GET drop-key and nothing else at gkm. §10.6's own and read rows and D-KEYS-26 change "any gkm token" to "a gkm token holding an r, rw or admin scope on some repo"; the rest of each row stands, and a token mixing deposit and r reaches them through its r. KEYS-M2-12's route matrix asserts deposit refused on POST /gkm/reader-key, POST /gkm/key-packages and GET /gkm/reader-key/<sidecar_id>.

Changes: D-KEYS-26; §10.6 own and read rows.

Questions: `g0-recheck-0-deposit-scope.md#2`.

### QD-181: Where does gkm count its per-uploader rates, given §22.7 allows it no Redis family for them?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §11, §2, §22, §9.*

Option 1. §10.6 says: gkm counts these limits per process, in memory, as §9.10 counts sockets', so each is the stated rate times the process count and a restart forgets it. That covers the 60 commits, the 60 claims, the STAGED bound and the 10 KeyPackage claims; the 24 h ReaderKey rule stays exact, read from the stored object. §11.13's classes row and §2.10's P0 row say per process, FS-117 reads "under its own rate in each process", and each limit is a GkmServiceSettings field. No Redis family, and no §2.8 or §22.7 change, since gkm-9 already gives rate limits as a purpose.

Changes: §10.6 checks and claim rows; §11.13 classes row; §2.10 P0 row; FS-117.

Questions: `plan-KEYS-rate-counters.md`.

### QD-229: §10.8 claims a window and veto that §7.9's table does not give most members
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §7.*

Replace §10.8's "a new device is admitted by the recovery key under §7.9's window and veto" (10-KEYS.md:610) with "a new device is admitted by the recovery key as §7.9's table says: at once outside the AdminSet, or at the cosign with self_admit off; through the 72 h window and veto for AdminSet members, k = 1 networks and restored bindings".

Changes: §10.8.

Questions: `g0-recheck-1-wr-n4-recovery-window.md#1`.

### QD-273: §10.4's kem row passes by construction: is the draft's KAT enough X-Wing evidence for the freeze?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §22.*

Recommended: option 1. Keep §22.10's rows and make the claim exact. §10.4's kem row takes §22.10's first clause, "X-Wing KATs from the draft's vectors pass for Go's crypto/hpke MLKEM768X25519", extended to DeriveKeyPair, and both rows say tmc/mls's comparison shares that code, so it checks wiring, not X-Wing. ARTIFACT.md states that the draft's vectors are the only independent X-Wing evidence. OpenMLS stays as §22.10's required row has it: needed only if a required step has a gap. The stacks row's tree, key schedule, framing and Welcome evidence stands.

Changes: §10.4 kem row; §22.10 kem row.

Questions: `plan-KEYS-interop-independence.md#2`.

### QD-280: D-KEYS-15 says gen/<g> is the only place a generation exists
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Change D-KEYS-15 and §10.5 from "is the only place a generation exists" to "is the only place a generation is created; a gen pack later holds it verbatim (10.16)", matching §10.6's row (10-KEYS.md:326-327). No behavior changes in this build.

Changes: D-KEYS-15; §10.5.

Questions: `g0-recheck-2-gen-pack-trigger.md#3`.

### QD-281: §10.8 says policy narrows kind defaults; nothing can
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

No document narrows a kind default; only hard denies remove access there. Delete ", which policy narrows" from §10.8's Key domains line.

Changes: §10.8.

Questions: `plan-ACL-small-readings.md#2`.

### QD-615: Should §10.5 fix the ladder's AAD widths as built (u64be for g and e, u8 for cause) and gen/1's cause as REQUEST? (keys-ladder-aad-widths, restated by section 6)
*Decided by the owner on 2026-11-10, asked one question at a time.*

§10.5's ladder AADs take the widths KEYS-M2-02 built: GenLink repo_id || u64be(g) || u8(cause) (25 B); GenWrap and LeafWrap group_id || u64be(e) || u64be(g) (32 B); GroupInfo group_id || u64be(e) (24 B). gen/1 carries cause REQUEST, and a reader refuses REMOVE there. Text only for design-records; testdata/gkm/ladder.json pins the bytes.

Changes: §10.5 text (design-records); testdata/gkm/ladder.json stands.

Questions: `details-6-ladder-aad-widths.md`, `keys-ladder-aad-widths.md`.

### QD-616: Which extension marks a last-resort KeyPackage, and at what type number? (keys-m2-07-last-resort, restated by section 6)
*Decided by the owner on 2026-11-10, asked one question at a time.*

A last-resort KeyPackage is marked by draft-ietf-mls-extensions' last_resort extension, type 0x000A, empty extension_data, in KeyPackage.extensions only and listed in every leaf's capabilities, as mls_extension.go builds it. Section 6.2.2's two rules apply: a device that joined through its last-resort KeyPackage self-updates at once and replaces it at its next upkeep pass. D-KEYS-12's suite migration moves the number if the draft's changes. design-records adds the line to §10.4's credential block (6.8).

Changes: DESIGN-DETAILS.md section 6 stands as written; §10.4 credential block line (design-records).

Questions: `details-6-last-resort-extension.md`, `keys-m2-07-last-resort.md`.

### QD-617: A re-formed group's epoch 0 carries no auth pin: should epoch 1's floor be gen/<the form's generation>'s auth? (keys-wire-reform-epoch-zero, restated by section 6)
*Decided by the owner on 2026-11-10, asked one question at a time.*

A re-formed group's epoch 0 carries no auth pin, and the epoch PUT check gives epoch 1 its floor from gen/<form.generation>'s auth, which plan-KEYS-reform-ladder's rule 5 requires to exist before any commit, wrap or claim. No wire change; one sentence in §10.6's epoch PUT check (design-records). DESIGN-DETAILS.md section 6 is built on this, and KEYS-M2-25 has landed it.

Changes: DESIGN-DETAILS.md section 6 stands as written; KEYS-M2-25 (landed) stands; §10.6 epoch PUT check sentence (design-records).

Questions: `details-6-reform-epoch-zero-floor.md`, `keys-wire-reform-epoch-zero.md`.

### QD-618: Welcome pointers keyed by (recipient, group, epoch): is `gkm/welcome/<sidecar_id>/<group_id>/<n>` approved? (keys-m2-13-last-resort-welcome-pointer, restated by section 6)
*Decided by the owner on 2026-11-10, asked one question at a time.*

Welcome pointers are keyed gkm/welcome/<sidecar_id>/<group_id>/<n> (n 20 digits), with the KeyPackageRef moved into GkmWelcomePointer.key_package_ref = 3; a device holding several pointers for one group takes the highest n above the newest epoch it reached. One Welcome, one key. The key form changes in §10.6, QD-442 and wrap_paths.json, with one proto field and gkm-5's wording (design-records), all unfrozen until M2's exit. DESIGN-DETAILS.md section 6 is built on this; KEYS-M2-19 carries the format change.

Changes: DESIGN-DETAILS.md section 6 stands as written; KEYS-M2-19 carries it; §10.6, QD-442, wrap_paths.json, gkm-5 (design-records).

Questions: `details-6-welcome-pointer-key.md`, `keys-m2-13-last-resort-welcome-pointer.md`.

### QD-637: Should a rotator read forwarding Delegations' reader keys in batches of up to 256, as it reads ReaderKeys, rather than by one GET each?
*Decided by the owner on 2026-11-10, asked one question at a time.*

gkm gains POST /gkm/delegation-keys {delegation_ids, at most 256} beside the GET, answering each stored forwarding reader key or none, in order, under the GET's scope (a reader of the network's config), as QD-066's POST /gkm/reader-keys does; one request and one reply message in gkm.proto with their gkm-1 lines, before M8's freeze. A config rotator reads delegation keys through it, about 13 requests a rotation at Team scale. Until it lands KEYS-M8-01 reads by the GET, one at a time.

Changes: KEYS follow-up: the batched route, its proto messages and the rotator's use of it; §10.14's routes and gkm-1 lines (design-records).

Questions: `keys-m8-01-delegation-key-batch-read.md`.

### QD-638: Who makes the group of a repo that a tagged or ephemeral sidecar creates, since KF1's epoch 0 needs its creator's leaf and an agent holds none?
*Decided by the owner on 2026-11-10, asked one question at a time.*

A tagged or ephemeral sidecar files the RepoCreate and places the repo, and stays its admin (owner decision 8). gkm hints pending to the network's config writers for a keying repo with no form; the first member device to act runs KF1's steps 2 to 4 as the group's creator (epoch 0 with its own leaf) and wraps generation 1 to the agent. Activation waits for that device, as an agent's every Add already does; a repo an agent creates while no member device is online stays keying until one returns. No format change; KF1 (§10.7) gains the second device (design-records). A KEYS follow-up builds the hint rule and the member device's step.

Changes: KEYS follow-up: gkm's pending hint for a formless keying repo; a member device forms the group and wraps gen 1 to the agent; KF1 §10.7 text (design-records).

Questions: `keys-m2-19-agent-created-repo-group.md`.

### QD-641: A 1,000-leaf group's join, path commit and resync measure 27 to 63 MB of heap above their baseline, three to six times DESIGN-DETAILS 6.4's "under ~10 MB": is the engine to be brought under the phone budget, or the budget and the claim changed?
*Decided by the owner on 2026-11-10, asked one question at a time.*

The MLS engine is brought under the phone budget in the review phase, measured by KEYS-M2-31's harness on the ios32 cell first. The owner directs that the SDK offload memory to storage wherever possible, since the iOS network extension and the apps have much more fast NVMe storage than RAM: hold the ratchet tree and other large state on disk and stream it (a path sealed and written a node at a time, the tree hashed and encoded from its on-disk sections, which mls_state.go already writes a node at a time), one decode for a resync, and a copy-on-write of the path in place of a whole-tree clone before a commit. No format or flow changes. Until then the harness reports the peaks and fails nothing on them. If the cell still reads over budget after this work, bounding a 32 MiB leg's roles is raised as its own question.

Changes: review phase: KEYS-M2-06, -08 and -09's engine files, storage-backed tree and streamed path; standing owner direction: SDK, apps and iOS extension offload memory to storage (BRIEF.md); DESIGN-DETAILS 6.4's memory row restated by the design agent.

Questions: `keys-m2-23-large-group-memory.md`.

### QD-642: Can a code-only device open its recovery wraps before it is admitted, or only fetch them?
*Decided by the owner on 2026-11-10, asked one question at a time. Also amends §7, §2.*

Before admission a code-only device fetches its recovery wraps under recovery:<member_id> and keeps the newest per group in its keychain; it opens them once admitted, when gen/<g> reaches it: first the config group's wrap, then the anchor, then the rest (gkm_recovery.go as built). Text only: §10.8, §7.9 and DESIGN-DETAILS 6.2.4 step 1 say 'fetches' where they say 'opens at once' (design-records; the design agent for 6.2.4). No format or scope change; §2.10's disclosure is unaffected.

Changes: §10.8 and §7.9 wording (design-records); DESIGN-DETAILS 6.2.4 step 1 wording (design agent).

Questions: `keys-m2-24-recovery-wrap-opens-before-admission.md`.

### QD-643: At which state does a member judge a GroupForm's signer, when the GroupForm carries no auth pin?
*Decided by the owner on 2026-11-10, asked one question at a time. Also amends §2.*

GroupForm gains bridge.AuthPin auth = 5, the signer's state when it signs. Members judge the form's signer by §10.6's rule at that pin where their retained log reaches it, and not at all before it, as R1's judged row does for every other judged statement; gkm holds the pin to its newest state as it holds a claim's (on the chain, not ahead). One field before M2's freeze and a §2.8 gkm-1 line for the form chain's pin (design-records). KEYS follow-up: gkmParseGroupForm reads the pin and GkmFormSignerAllowed runs at state.At(pin); the re-forming client fills it. Until then the client judges at the newest state, refusing with an alarm.

Changes: KEYS follow-up: GroupForm.auth = 5 in gkm.proto, gkm_reform.go judging at the pin, gkm's check, tests; §10.6 GroupForm row and §2.8 gkm-1 line (design-records).

Questions: `keys-m2-25-groupform-signer-judged-at.md`.

### QD-644: What should Gkm.tla's `MembersSkipRosterCheck` twin show, when the model's reach is computed from the store and a bad commit breaks the invariant the moment it stands?
*Decided by the owner on 2026-11-10, asked one question at a time.*

Gkm.tla models what a member's refusal buys: a poisoned set of generations and an Inject action for a hostile leaf's commit; members that process it refuse and poison its generation; Seal refuses a poisoned generation; the invariant is that no content sealed after the injection is readable by the dropped leaf. The MembersSkipRosterCheck twin lets Seal use the poisoned generation and must break it. About 40 lines of model and one invariant, by the design agent (section 6.6's record) within the disk rule.

Changes: sidecartest/model/details/Gkm.tla and DESIGN-DETAILS 6.6 (design agent).

Questions: `keys-m2-19-members-skip-roster-twin.md`.

### QD-343: What does 'tmc/mls under 0x004F mapped to 0x0010' mean, when the suite number is inside signed bytes?
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

"Mapped" means patched. mlsinterop/ builds tmc/mls at v0.0.0-20260930074835-1c42a372504a with one build overlay changing wire.go:39's constant from 0x004F to 0x0010, which no other tmc/mls suite uses, so both stacks sign and hash one number and testdata/mls/0x0010/ holds genuine 0x0010 transcripts. ARTIFACT.md records the patch, and that tmc/mls cites draft -06 where §10.4 cites -07.

Questions: `plan-KEYS-interop-independence.md#1`.

### QD-441: Row (d): the KDF and AEAD of HPKE-XWing
*Proposed fill: a gap the agents filled; work builds on it. Also amends §11.*

HPKE-XWing means KEM 0x647a, KDF HKDF-SHA256 (0x0001), AEAD AES-128-GCM (0x0001), base mode, by crypto/hpke's NewSender and Sender.Seal, since hpke.Seal takes no AAD. It holds for ReaderWraps, DelegationWraps, RecoveryWraps and deposit slots; a deposit slot uses info "UR evs 1.0 deposit" and aad = repo_id || u64be(g) || slot_id.

Changes: §10.5 HPKE-XWing; §11.12 deposits row.

Questions: `plan-KEYS-wire-gaps.md#4`.

### QD-442: Row (g): padding and id encoding in gkm's object keys
*Proposed fill: a gap the agents filled; work builds on it. Also amends §7.*

In gkm's keys, <n>, <g> and <seq> are 20 decimal digits, zero-padded, as proj/ is (§7.9); <seq> starts at 1. sidecar_id, member_id, repo_id and group_id are 32 lowercase hex characters with no dashes, not Id.String()'s form; delegation_id and <ref> are 64; c8, k8 and b8 are 16. s: and d: are literal ASCII prefixes. testdata/gkm/wrap_paths.json pins these.

Changes: §10.6 object table.

Questions: `plan-KEYS-wire-gaps.md#7`.

### QD-463: Numbers for ReaderKey, GkmHint and GkmHintKind
*Proposed fill: a gap the agents filled; work builds on it.*

As landed in gkm.proto: ReaderKey{sidecar_id = 1, xwing_public_key = 2, int64 not_after = 3}, in ms since the epoch, keeping §10.5's name, as plan-KEYS-wire-gaps.md#2 also answers; GkmHint{group_id = 1, epoch = 2, kind = 3, recipient = 4}, recipient as bytes in the wrap path's s: or d: form; GkmHintKind COMMIT 1, PENDING 2, WELCOME 3, KEY_PACKAGES_LOW 4, WRAP_PENDING 5. design-records writes them into §10.14.

Changes: §10.5; §10.14.

Questions: `protos-services-unwritten-numbers.md#2`.

### QD-464: Row (m): POST /gkm/groups against POST /gkm/repos/<id>/forms
*Proposed fill: a gap the agents filled; work builds on it.*

POST /gkm/groups serves creation and takes all three bodies: the Signed GroupForm, epoch 0 and generation 1's Signed GenRotate, written in that order, each If-None-Match, equal bytes answering success, so KF1 resumes after a crash. POST /gkm/repos/<id>/forms serves only a re-form.

Changes: §10.14 routes.

Questions: `plan-KEYS-wire-gaps.md#13`.

### QD-465: Row (k): how holders_sha256 sorts and joins
*Proposed fill: a gap the agents filled; work builds on it.*

holders_sha256 = SHA-256 of the identities sorted ascending by bytes.Compare and concatenated with no separator or count. Identities are 17 B (kinds 1, 2 and 4: the kind byte and a 16-byte id) or 33 B (kind 3: the kind byte and a 32-byte delegation_id), so the kind byte fixes each length, and each appears once, KeyHolders being a set.

Changes: §10.5 identity bytes.

Questions: `plan-KEYS-wire-gaps.md#11`.

### QD-466: Row (l): the drop key pair's derivation and the Delegation seed's mapping
*Proposed fill: a gap the agents filled; work builds on it. Also amends §7.*

Drop pair: hpke.MLKEM768X25519().DeriveKeyPair(K_drop), K_drop being the 32-byte `drop` derivation of RK_g. Delegation: hpke.MLKEM768X25519().NewPrivateKey(delegation_reader_seed), X-Wing's own 32-byte seed, and reader_xwing_public_key is its public key's bytes.

Changes: §10.5 drop purpose; §7.8 AuthKeyBundle.

Questions: `plan-KEYS-wire-gaps.md#12`.

### QD-467: Row (f): bodies of epoch/<n>, group-info, the Welcome pointer and <ref>.claim
*Proposed fill: a gap the agents filled; work builds on it.*

Four messages in protocol/gkm.proto. GkmEpochObject{bytes commit = 1; GkmCommitHeader header = 2; bytes uploader = 3; int64 time_ms = 4; bytes gen_wrap = 5; bytes sealed_group_info = 6; uint64 group_info_generation = 7; bytes network_id = 8; uint32 cipher_suite = 9}: fields 8 and 9 in epoch 0 only, whose commit is empty and whose uploader is gkm-1's creator. GkmGroupInfoObject{uint64 epoch = 1; uint64 generation = 2; bytes sealed_group_info = 3}: epoch alone is the pointer, all three above 16 leaves. GkmWelcomePointer{bytes group_id = 1; uint64 epoch = 2}. GkmKeyPackageClaim{bytes group_id = 1; bytes claimer = 2}. A Welcome or KeyPackage object is the MLSMessage bytes themselves. gkm.proto's header comment drops "none is declared here".

Changes: §10.6 objects.

Questions: `plan-KEYS-wire-gaps.md#6`.

### QD-468: Row (c): RecoveryWrap's body, HPKE info and AAD
*Proposed fill: a gap the agents filled; work builds on it.*

RecoveryWrap is unsigned, bare enc || ct, 1,168 B: 1,120 B enc, a 32 B RK_g and a 16 B tag. HPKE base mode, info "UR evs 1.0 recovery", aad = member_id (16 B) || group_id (16 B) || u64be(g) || C_g (32 B) || SHA-256(the binding's Ed25519 key)[0:8], the raw bytes b8 spells in hex.

Changes: §10.5 RecoveryWrap; §10.6 sizes.

Questions: `plan-KEYS-wire-gaps.md#3`.

### QD-469: Row (e): ur_group's extension number and encoding
*Proposed fill: a gap the agents filled; work builds on it. Also amends §17, §2.*

ur_group is GroupContext extension type 0xF553, RFC 9420 §17.3's private use, listed in required_capabilities. TLS presentation with RFC 9420 §2.1.2's vectors: struct { opaque network_id<V>; opaque repo_id<V>; uint8 kind; opaque owner_member_id<V>; }. kind is the RepoKind number in acl.proto, general 1 to secret 9; owner_member_id is empty when the repo is not owner-bound.

Changes: §10.5 ur_group.

Questions: `plan-KEYS-wire-gaps.md#5`.

### QD-471: Numbers for GroupForm, which only §2.8's gkm-1 lists
*Proposed fill: a gap the agents filled; work builds on it. Also amends §2.*

As landed: GroupForm{repo_id = 1, group_id = 2, previous_group_id = 3, generation = 4}, its signer being Signed's, and design-records adds the fence to §10.6. These are numbers only: what a re-form checks, and any field that adds, is plan-KEYS-reform-ladder's.

Changes: §10.6.

Questions: `protos-services-unwritten-numbers.md#3`.

### QD-526: Bodies for §10.6's objects and §10.14's routes, which §10 names and gives no bytes
*Proposed fill: a gap the agents filled; work builds on it.*

Accept rows 1 to 10 as landed in protocol/gkm.proto, every route `x-status: planned`, and design-records folds them into §10.14. Row 4: `GET /gkm/welcomes` answers each pointer with its Welcome. Row 7: the epochs and gen lists stop at gkm's bound, and a client asks again after its last item. The three items it left open follow plan-KEYS-wire-gaps#8, plan-KEYS-wire-gaps#13 and plan-KEYS-wrap-route-rate.

Changes: §10.14.

Questions: `keys-wire-route-bodies.md`.

### QD-528: Row (b): ReaderKey as a proto message
*Proposed fill: a gap the agents filled; work builds on it.*

ReaderKey stands as landed in protocol/gkm.proto: sidecar_id = 1, xwing_public_key = 2, not_after = 3, an int64 of ms since the epoch. The name stays not_after, §10.5's own, not the question's not_after_ms.

Changes: §10.5 ReaderKey unit.

Questions: `plan-KEYS-wire-gaps.md#2`.

### QD-569: Nine risks carry two ratings in different sections
*Proposed fill: a gap the agents filled; work builds on it. Also amends §11, §15, §19, §21, §22, §23.*

One rating each, the higher of the pair: rogue admin admits a device Medium/High (fix 10-KEYS.md:869); site or Hurricane Electric outage Medium/Critical (15-MAIL.md:419); costs hold a set below ~400 pushes/s Medium/High (19-OPS.md:959); Sybil free networks High/High (21-ABUSE.md:214); iOS jetsam regression Medium/High (22-TEST.md:2777); no ACL document High/High (21-ABUSE.md:216); purge bug Low/Critical (11-EVS.md:3133); site loss Low/Critical (11-EVS.md:3116); no indexer designated High/Medium (23-PHASE.md:296).

Changes: §10.15; §11.21; §15.16; §19.17; §21.17; §22.16; §23.15.

Questions: `g0-density-text-alignments.md#10`.

### QD-588: C_g sits in a paragraph, not a fence
*Settled by the agents from the design; work builds on it.*

C_g = SHA-256("UR evs 1.0 commit" || repo_id || u64be(g) || RK_g), as written. design-records moves that line into §10.5's fence unchanged, which clause 2 of the density rule asks.

Changes: §10.5.

Questions: `g0-density-text-alignments.md#8`.

<a id="s11"></a>
## §11 Encrypted versioned storage

### QD-011: A re-creation's fold or a path-epoch copy can drop a marker's carried ids, so the published ttl fails and the content stays for good
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

Carried ids never leave with their entry. Before a write or delete would drop them, the fold or copy first PUTs an orphan marker at idx/<repo>/<ref>/_o/<r as 20 digits>-<first 8 B of SHA-256(ids) in hex>.e (If-None-Match, equal bytes on 412 success) holding {removing push id, r, token path, kind-5 segment ids, slot ids}, then proceeds, so a crash only repeats the PUT. The cases are a fold's creation over a marker with carried ids, a fold's creation over an entry whose newest versionless version a prefix removal in the same fold range did not list (no marker was ever written), and a copy's unmoved delete of a source marker with carried ids. §11.7's collect row adds one LIST of idx/<repo>/<ref>/_o/ per ref and collects each with r at or below the window's through exactly as a marker: the same margins, clock and hold rules, a hold leaving it for a window after the hold ends. It deletes only ids the path's newest version does not name. The key sits outside any epoch, so copies never move it. evs-4's and evs-5's ttls then hold as published, and evs-11's store row gains the key.

Changes: §11.7 fold row; §11.7 collect row; §11.6 copy row; §11.8 idx/ row; §2.8 evs-11; FS-67.

Questions: `plan-EVS2-marker-carried-ids.md`.

### QD-058: A hold's stored form and columns are undefined
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §21, §2.*

[plan-ABUSE-hold-format#2] The object is UTF-8 JSON, at most 1 KiB, keys in this order: {"version":1,"network_id":"<id>","case_id":"<id>","kind":"preserve_2703f"|"report_2258a","scope":"network"|["<repo_id>",...],"place_time_ms":<int>,"expire_time_ms":<int>}. Unsigned. A renewal rewrites it If-Match, keeping `place_time_ms`. A body that does not parse, or an unknown version, kind or scope, covers the whole network; a record past `expire_time_ms` is no hold. The table is `abuse_legal_hold(network_id, case_id, part, kind, scope, place_time, report_time, renew_time, expire_time, copied_rows, copy_state)`, primary key on the first three. `renew_time` set refuses a second renewal, and `report_2258a`'s deadline runs from `report_time`. §11.8's row, api-14 and evs-19 name these fields. [plan-ABUSE-metadata-rows#2] As plan-ABUSE-hold-format.md#2: api-14 and evs-19 gain `place_time`, and api-14 also `report_time`, `renew_time`, `part` and `copy_state`.

Changes: §11.8; §21.9; §2.8 api-14; §2.8 evs-19.

Questions: `plan-ABUSE-hold-format.md#2`, `plan-ABUSE-metadata-rows.md#2`.

### QD-061: taskworker cannot find a repo's network, so a hold could miss a repo
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

Option 1. Add network_id to repo/<repo> at creation: EvsRepoObject field 10, set from the token's network, checked against the projection's AclRepo, never changed, and kept in the shredded tombstone. §11.8's repo/ row lists it, and evs-1 reads 'its network, stored at creation'. taskworker matches hold/ and reports stored bytes from it. A re-seed writes it from the projection. A reader that finds it absent treats the repo as held and keeps everything.

Changes: §11.8 repo/ row; §2.8 evs-1; §11.12 Naming and creation.

Questions: `plan-EVSB-repo-network.md`.

### QD-069: A depositor loses any usable base on its own deposit ref, since every read route refuses it and a CONSUME moves the chain
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Keep every read route closed, so FS-23 stands as written, and hand the depositor the head where it already talks to evs. Add EvsDepositHead {version, chain} to evs.proto; it needs no path epoch, since plan-EVS1-epoch-kinds.md#2 keeps deposit refs at epoch 1. (1) A push's 200 on the caller's own deposit ref carries it: for a commit, the version committed; for a 5a retry, the current head. (2) 5f's refusal on the caller's own deposit ref carries it, read from the cluster head. Name file mode's 5f refusal 409 BASE_STALE in §11.20; the refuse row already makes it final, so nothing is recorded. (3) The depositor keeps the newest EvsDepositHead in its sealed store and builds each push on it. After BASE_STALE it rebuilds under a new push id and new slot ids, keeping receipts under 24 h old. A new ref's first push uses version 0 and C_0, which it can compute. (4) §11.12 says plainly that a depositor learns its own ref's version and chain, so it can infer that and when a reader consumed, and nothing else of the head. (5) FS-23 adds two cases: 130 CONSUME versions between two deposits, and a depositor restarted with no state, each recovering through the refusal with every read route still refused. plan-RECORD-depositor-spool's consumed_through rides this same message.

Changes: §11.8 step 8 and 5f; §11.12 Deposits; §11.20 push refusals; FS-23.

Questions: `plan-EVS1-deposit-head.md`.

### QD-095: No route moves a repo from keying to active, so no repo could ever open
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §10.*

Option 1. Add POST /evs/v1/repos/<id>/activate (admin), no body, to C11 and §11.20. evs reads repo/ from the cluster. keying: it lists gkm/repo/<id>/, reads the newest GroupForm, HEADs gkm/<group_id>/gen/1 and CASes repo/ to active by If-Match; no GroupForm or no gen/1 answers 409 GROUP_NOT_READY. active: 200, so a retry is harmless. Any later state: that state's refusal. The write is P1 for the creating network. evs cannot see whether wraps are complete, so KF1's order on the creator stays the guarantee. §11.12's state row names the route, and FS-20 adds a kill after the CAS.

Changes: §11.12 state row; §11.20 API routes; §10.7 KF1; C11; FS-20.

Questions: `plan-EVS1-repo-activate-route.md`.

### QD-096: At a re-seed, a slot holding an erased key beside live keys: strip or refuse
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §19.*

evs strips. §11.13's row reads: evs applies every ERASE before it serves a slot, accepts a slot only if a re-seeded version names it, and strips from it every key an ERASE it holds covers, as an ERASE's rewrite does, leaving key indexes unchanged; a slot left with no key is not stored. An ERASE taken after a slot rewrites it as at commit. §19.10 says the same and gains "a re-seeded version names it". §11.8's fence gains: on a re-seed a 412 compares bytes after stripping. §11.12's device-side subtraction stays as an optimization. /reseed gains no refusal. FS-41 adds a slot with one erased and one live key: the erased key is gone and the live one reads.

Changes: §11.8; §11.12; §11.13; §19.10; FS-41.

Questions: `g0-recheck-2-reseed-slot-keys.md#1`.

### QD-099: A rename in a slot-keyed repo needs the removed path's slot, which 5h and I-EVS-10 forbid
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Extend the rename exception to slots. 5h: a version the push creates may name the slot of a path this push removes, and a versionless version's kind-1 locators may come from that path too. I-EVS-10's last clause: 'a versionless path's slot only that path's versions and, in turn, the rename target of the push that removes it'. §11.7's keys row likewise. Add one rule the text lacks: each kind-5 segment or slot of a removed path is named by at most one new version of the push, else 409 VERSIONING, checked across parts at the seal. The target then reuses the key until checkpoint rule (4), a CLOSURE or a rekey. Staged segments stay uncited, and a rename re-stages them. FS-64 gains a slot-keyed case and a two-target refusal, and EvsCommit.tla's I-EVS-10 follows.

Changes: §11.8 5h; I-EVS-10; §11.7 keys row; D-EVS-36; FS-64; FI-17.

Questions: `plan-EVS2-slot-rename.md`.

### QD-101: What seals a deposit's record headers, entry fields and metadata, since a depositor holds no manifest key
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §15.*

Seal them under a key derived from the deposit's own object key: K_dep = HKDF-SHA256(object key, salt repo_id, info "UR evs 1.0 deposit"). K_dep seals the record header (#3's layout, key_ref_kind 1) and EvsEntryVersion.sealed_fields, with §11.6's AEAD and nonce rules. §15.7's sealed header is plan-MAIL-deposit-shape's trailer, which is body, under the object key. A deposit push's sealed metadata goes under the K_dep of its first entry. Bodies stay under the object key itself. sealed_ref_name stays empty and deposit entries carry no name row, since their tokens are random ids. A reader takes the slot from the entry's cleartext slot_ids, opens it with the drop private key, then derives K_dep. §11.6's record row reads 'sealed under manifest, or on a deposit ref under K_dep'.

Changes: §11.6 record row; §11.12 deposits row; §15.7 Deposit.

Questions: `plan-EVS1-format-bytes.md#5`.

### QD-153: A flat listed_sha256 cannot prove a list range, so §11.9's membership proof does not exist
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Delete 'and the list range proving membership' from §11.9's reply row. A head reader decides membership from the signed body alone: version V is listed iff some EvsDropPath's lineage holds V's token path in V's epoch, V is below through_version, and V has an entry. Every reader checks drop_sha256 over the body. listed_sha256 and the listed-set equality move to the replaying clause of §11.7's states row, since only a replaying reader holds the whole list. listed_sha256 stays a flat hash, and §11.13's resolve still proves the list exact before anything is deleted. No format change.

Changes: §11.9 reply row; §11.7 states row; §11.9 dropped row.

Questions: `plan-EVS2-drop-list-proof.md`.

### QD-155: Format-1 evs answers a format-2 construct 409 FORMAT_UNSUPPORTED, recorded, and 5c and the refuse row must say so
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §19.*

Option 1. (1) Format-1 evs answers a format-2 construct in a push, part or seal 409 FORMAT_UNSUPPORTED {needs_format: 2}, added to §11.20 and the code table. (2) In the refuse row FORMAT_UNSUPPORTED is recorded, and so is 5c's 409 VERSIONING from §19.11's gate or a repo lock; 5c's VERSIONING from kind or ref rules is final. (3) 5c's 'repo's format' VERSIONING stays a format-2 evs's answer outside the gate. (4) A format-2 repo/ on a format-1 binary answers 503 with Retry-After before step 4 and writes nothing, as §11.6 and FS-72 say; it refuses nothing, so I-EVS-3 needs no record. (5) FS-72 adds a rolling case: a format-1 evs refuses, and a format-2 evs in the gate meets the retry and answers the recorded refusal.

Changes: §11.8 5c and refuse row; §11.20 push refusals; FS-72.

Questions: `plan-EVS1-format-unsupported.md`.

### QD-167: A multi-part DROP's body and lists have no field in EvsPushPart, and neither does any other payload section
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Before format 1's bytes freeze at M2's Gn-out, add one general field to EvsPushPart: `bytes sections = 8`, this part's slice of every payload section §11.6's payload row names beyond fields 3-6: the part hashes, new-objects list, new slot bodies, erased list, a DROP's body and lists, tail moves, source paths, reuse list and Merkle proofs, in that row's order and EVS-FORMAT.md's framing. Concatenated over the parts in part order, the slices equal what a one-part push carries. A DROP rides as two sections of that framing (plan-EVS1-format-bytes#7's 9 and 10): its EvsDropHistory bytes, then each EvsDropPath's list in `paths` order as bare 32 B values; a slice may split anywhere. parts_sha256 covers it because it sits inside EvsPushPart, and it counts against the part's 1 MiB. The seal, never a part, runs the DROP's body and list checks, streaming the slices, since only the seal reads every part. Format 1 needs no new refusal: flag 256 already refuses a DROP as FORMAT_UNSUPPORTED before the section is read. Lists are not capped to one part.

Changes: §11.6 EvsPushPart; §11.6 payload row; §11.8 parts row; §11.8 part record.

Questions: `plan-EVS2-drop-list-parts.md`.

### QD-173: §11.14's shrink row is false for front-coded blocks, so a CLOSURE rewrite can outgrow its pad and stall an erasure
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §22.*

Any rewrite padded to a replaced length (a CLOSURE, a DROP's rewrite, a roll-up's step-4 rewrite) first builds the shard canonically, in blocks of 64. If that fits the replaced length, it pads and is done. If not, it rebuilds keeping the replaced shard's block partition: each block keeps its surviving keys, prefix sharing resetting at each block's first key, and an emptied block goes. A removed key saves at least 4 B and costs the next key at most 2, so this always fits. The rewrite keeps the replaced header's pad_generation. Decoders accept blocks of 1 to 64 keys and refuse an empty or larger one, re-encoding from the file's own partition. Merges and roll-ups always re-block by 64. Both outcomes are functions of the inputs, so reproduction holds. §11.14's shrink, dictionary and determinism rows say so, and §11.12's residual row discloses that a short block shows current readers roughly which key ranges only the erased document held, until the next merge.

Changes: §11.14 shrink row; §11.14 dictionary row; §11.14 determinism row; §11.12 residual row; §22.6 index files; FS-78.

Questions: `plan-SEARCH-shrink-claim.md`.

### QD-176: A depositor cannot see a CONSUME, so D-MCP-10's "spool until consumed" has no mechanism
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §16.*

The ingester declares a mark in its CONSUME: `EvsPush.consumed_through` (uint64, field 35), the highest version of this deposit ref at or below which no unconsumed deposit remains, by its own read. evs copies it to `EvsHead.consumed_through` (field 27), never falling, and returns it beside {v+1} in a deposit push's 200 and in plan-EVS1-deposit-head's refusal body. The depositor stores each spooled deposit's push version and prunes at or below the mark; everything else stays within §16.7's 1 GiB, oldest dropped first, coverage naming spool_drop. No age bound: ingest lets no outcome hold a ref back (RECORD.md section 5.4), so the mark does not stick, and 30 days would drop exactly an offline author's deposits. §2.8 evs-3 gains the field and says a depositor, receipt-only readers included, learns when its deposits were ingested.

Changes: §11.6 EvsPush; §11.8 EvsHead and the 200 reply; §2.8 evs-3; §16.8 Mirrors and site loss; RECORD.md sections 5.4 and 5.7.

Questions: `plan-RECORD-depositor-spool.md`.

### QD-179: drops/<repo>/_ cannot hold what its limits allow, and its 30-day expiry already loses cancelled and refused drops
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

Keep 64 KiB. (1) The table holds fixed-size records only: a drop at most 128 B (ids, ref, push id, version, place, not_before_ms, state, phase, freed and held bytes, preview_id), a dry run at most 64 B, the running job at most 256 B, which also points at any job still holding ids. A dry run's paths, lists and results and a job's snapshots, covered drops and sets go in dropscan/. (2) An entry leaves 30 d after it ends, or sooner when a write would pass 64 KiB: ended entries go oldest first, never one whose DROP committed under 27 h ago, since evacuation re-appends a committed DROP the table lacks. Pending, executing and observed entries never leave. (3) A held entry occupies, lists and leaves the table exactly as its done twin would, its resume state in the job's dropscan/ held files, so no count or listing shows a hold. (4) A cancelled or refused drop leaves a 17 B void record {drop_id, state} for the repo's life; an entry absent with no void record means executed, which is the safe default for §11.9's serve row. (5) 5c reads the table for a drop and answers 429 when pending, executing and observed entries plus void records would pass 48 KiB. Held entries never count, a cancel is never refused, and dry runs only evict. evs-28's ttl becomes 'at most 30 d' plus the void record, whose id every DROP statement already holds.

Changes: §11.8 drops/ row; §2.8 evs-28; §11.13 who row; §11.9 serve row.

Questions: `plan-EVS2-drop-table-bound.md`.

### QD-198: evs cannot answer DROP_PATH for ur/index, ur/lfs and .ur-index/, because X2 hides ref and path names from it
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

evs answers 409 DROP_PATH when a lineage's head is a directory entry or versioning 2, and 409 VERSIONING when it is versioning 1, both recorded by §11.8's refuse row. The reserved names are refused by name at honest clients and by readers: a DROP whose lineage resolves to ur/index, ur/lfs or .ur-index/ raises history_drop in state invalid, naming the signer, and readers ignore its written version there, as §11.7's setting row already ignores any version under an index root that no §11.14 mechanism wrote. §11.7's refused row and D-EVS-62's 'derived refs' say who refuses what, and FS-95's ur/lfs case expects VERSIONING at evs plus the client refusal. Disclose the residual in §11.7: an admin on a modified client can drop old versions of a versioned file there (`<root>/settings`, ur/lfs's settings, or an ur/lfs object written at versioning 0 under a since-lifted lock), the head staying each time.

Changes: D-EVS-62; §11.7 refused row; FS-95.

Questions: `plan-EVS2-drop-path-visibility.md`.

### QD-202: Local git over HTTP has no credential
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §7, §4, §5, §15.*

[plan-EVS1-git-http-credential] Option 1, for https off loopback too. At ur mount add the daemon draws 32 random bytes per mount, kept in the sealed store (§5.9). The http front takes Basic with username ur and that secret, compared in constant time, and answers 401 otherwise. git-credential-ur is a local helper: it dials the daemon's control socket, where §5.8's peer-uid check is the real authentication, and prints the username and secret for a host and port the daemon serves, nothing for any other. ur mount add and ur mount share set credential.<url>.helper in the clone's config. The secret never enters a remote URL, an environment variable, MCP output or a log, and it grants only what the daemon grants its OS user, as §15.10's credential does (owner decision 47). No service token is involved, so I-7 takes no exception. Keep git-credential-ur in §7.17 and add it to §4.10 and §11.11; drop only §7.8's 'but for §11's v1 read-only git view', which differs from plan-TEAM-git-credential-ur's option 1. If cli/UI.md turns up and says otherwise, it wins. [plan-TEAM-git-credential-ur] Delete ", but for §11's v1 read-only git view" from §7.8's Token exchange bullet. `git-credential-ur` stays in §7.17 as plan-EVS1-git-http-credential's local helper, which holds a per-mount secret and no service token. Service tokens never leave the daemon, and git reaches a repo only through §11.11's local server and `git-remote-ur`.

Changes: §11.11 Binding; §7.8 token exchange; §7.17; §4.10; §7.8.

Questions: `plan-EVS1-git-http-credential.md`, `plan-TEAM-git-credential-ur.md`.

### QD-209: A push that changes no document reads as unindexed, and on a phone-only ref it stays that way
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Format 2 adds `index_none` to a push's sealed metadata, under sealed_metadata_sha256. An index-aware writer sets it when its push changes no document: every changed path falls under §11.14's never row, or is binary or skipped with no prior indexed version (a version that turns binary is already a tombstone). A push then counts toward indexed_through if it changes its writer's head, a coverage reaches it, it touches only .ur-index/ or ur/index, or it carries the mark. A reader may classify a mailbox's non-m/ token prefixes with no fetch. Hosts with the text check a marked push as an omitted document (D-EVS-56), raise index_mismatch naming the signer, and re-enter it as a backfill. An old client's push has no mark and stays unindexed until backfilled. Nothing server-visible changes.

Changes: §11.14 coverage rows; §11.14 in-ref row; §11.6 sealed metadata; FS-74.

Questions: `plan-SEARCH-no-document-pushes.md`.

### QD-215: `pad` cannot add 1, 2, 130 or 16,387 bytes, and SearchFilters has no cap, so some bodies cannot be sized
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §16.*

Builder rule, no wire change: every field but `pad` stops at the body's size less 131 B, so `pad` is at least 131 B and its length varint two bytes, which removes the 1, 2 and 130 holes. A multi-step reply whose pad would be exactly 16,387 B holds one hit back. A reply holds hits for the next page. Cap one thing: SearchFilters at most 768 B encoded in a SearchRequest. Page 0 then holds at most 2,987 + 3 + 768 = 3,758 B against the 3,885 B budget, so every request fits and none needs splitting. The indexer answers a larger one INVALID, and §11.14's status row and §16.10 say so. A search whose filters pass 768 B stays on the device with FallbackReason `none`; local search keeps no such cap. A body that cannot be sized is never sent short.

Changes: §11.14 sizes row; §11.14 status row; §16.10 filters; FS-83.

Questions: `plan-SEARCH-exact-body-sizes.md`.

### QD-218: Nothing says when a member's vault is made, and "one per member" has no refusal behind it
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §16, §10.*

§11.12 and §16.8 state this: the first consented, not read_only device of member M with an entry to write files RepoCreate{kind vault} (§10's KF1). M's vault is M's live vault repo whose RepoCreate has the lowest log position, live as RECORD.md section 4.2 reads it, and writers, depositors and readers all use that rule at their pin. Once its RepoCreate lands, and before its first write, a device reads the log; if another repo is the vault, it ingests any deposit into that one and files RepoDelete{now} for its own empty repo.

Changes: §11.12 kinds; §16.8 logs table.

Questions: `plan-RECORD-small-readings.md#3`.

### QD-219: evs must answer `collected` by a time rule, since §11.9's 404 test cannot deliver FS-66 or keep a hold hidden
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Let T be the end of the UTC minute in the replacing record's EvsPlace, plus 60 s. Before T evs serves a replaced versionless version; from T every read of it answers `collected` by evs's checked clock, whether or not its bytes remain (staged in a batch, purge: observe, or kept by a hold). §11.9's collected row becomes 'a replaced versionless version from T, and any version whose kind-5 segment or staged range 404s'. FS-66 reads 'by 120 s'. Never use time_ms, which may trail the commit by 10 min (30 for a seal). Client reads must stay version-addressed so that the rule always applies.

Changes: §11.9 collected row; FS-66.

Questions: `plan-EVS2-small-readings.md#5`.

### QD-244: §11.13's equations need fields that its reports row and evs-10 do not carry
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §19.*

Option 1. Add to §11.13's reports row and evs-10's sees, per process every 5 s: priced bytes issued by class (P1, unfunded P2, funded P2), priced bytes in flight, and the funded backlog by P2 rank (evacuation, page-out folds, other folds, copies, packing, retention, GC, drops). The loop sums them: k is measured bytes over all priced bytes issued in the last 10 min, P0's included; T and A2 subtract in-flight; A2 is handed out rank by rank. Add a per-cluster at_limit flag to {nvb_<set>}, which the budget loop sets from FileClusterAdminInfo at 80% summed raw use or 70% inodes (§19.9). evs reads it with its allowance and keeps the last value while the key is absent. No network or repo id, and no new ttl.

Changes: §11.13 reports row; §2.8 evs-10; §19.6 budget row; §19.9 cohorts row.

Questions: `plan-EVSB-nvb-fields.md`.

### QD-251: evs cannot quote x402 terms
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §20.*

evs answers 402 with the `QuotaRefusal` body, `upgrade: true`, and no terms; only api-hosted routes quote them. §11.20's segment row and §20.7's mapping comment say so.

Changes: §11.20; §20.7.

Questions: `plan-QUOTA-small-readings.md#18`.

### QD-256: x/text's cases.Fold() swaps Cherokee case, so normalizer 1 is not idempotent and Cherokee search misses
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Normalizer 1's case-fold step is cases.Fold() followed by a fixed map, U+AB70-U+ABBF to U+13A0-U+13EF and U+13F8-U+13FD to U+13F0-U+13F5, before the accent step, published with its tables so SearchOracle applies it too. testdata/index/ gains two vectors: U+13A0 and U+AB70 both give U+13A0, U+13F0 and U+13F8 both give U+13F0. The map is a no-op on a correct fold, so a later x/text fix changes no output, and a module bump is another normalizer anyway.

Changes: §11.14 text row; §11.14 tables row.

Questions: `plan-SEARCH-cherokee-fold.md`.

### QD-258: ur/lfs's signed settings file has no path, bytes, signer rule or command
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §8.*

A versioned file `settings` at ur/lfs's root, one path component of those 8 bytes, versioning 0 in every repo though the store's objects are 1, written as an inline record. Body: `message EvsLfsSettings { uint32 window_days = 1; }` in evs.proto, marshaled deterministically and sealed as any file, so it needs no §2.8 row. N is 30 when the file is absent or window_days is 0; 1-6 read as 7; 7 or more as written. A version counts only if its push's signer held repo admin (§8.8) at that push's auth pin; else devices alarm and use the newest version such a signer wrote. A prune reads it at its start s. `ur evs lfs window <days>` writes it, 7-365. An 8-letter top-level name cannot collide with an object's 2-character first directory.

Changes: §11.11 prune row; §11.7 choose row; FS-73; evs.proto (new message).

Questions: `plan-EVS2-lfs-settings.md`.

### QD-270: ur/lfs objects must never stage, which narrows D-EVS-36 and §11.7's staged row
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

An ur/lfs object of any size is a kind-5 upload, never staged, so a touch always cites it. §11.7's staged row, §11.8's step 2 and D-EVS-36 gain 'except ur/lfs objects'. evs refuses nothing new, since 5h already takes a small kind-5 upload. ur/lfs's settings file is versioned and unaffected.

Changes: D-EVS-36; §11.7 staged row; §11.8 step 2.

Questions: `plan-EVS2-small-readings.md#8`.

### QD-286: EVS1-M2-01, -04 and -05 write format 1's missing bytes, and design-records folds them in before Gn-in
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Option 1. EVS1-M2-01, -04 and -05 write protocol/EVS-FORMAT.md from rows #2 to #9 and pin it in testdata/evs/ vectors, and design-records folds it into §11.6 before M2's Gn-in, where peer review judges real bytes. Rows #4 and #5 are not layout, so they take their own answers first.

Changes: §11.6 (additions only).

Questions: `plan-EVS1-format-bytes.md#1`.

### QD-300: Who writes down §11.14's open byte layouts before format 2's vector schemas are fixed
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

SEARCH-M10-01 writes `protocol/INDEX-FORMAT.md` with the values in rows #1 to #8, pinned by testdata/index/ vectors, and the design-records track folds them into §11.14 for Gn-in's peer review. Nothing waits on the design team.

Questions: `plan-SEARCH-index-format-bytes.md`.

### QD-337: ERASE notes: the erasure's id is the request's id
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The runner's `erasure_id` is the `DirectoryErasureRequest.request_id`, carried in §11.12's existing sealed note, so no note field is added. Racing runners and the 30-day sweep share that one id, and RECORD.md's `ErasureBody.request_id` holds the same value.

Questions: `plan-RECORD-small-readings.md#12`.

### QD-387: A term running past the 256 B overlap misses across a chunk boundary, with no FI-18 exception needed
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The 256 B overlap stands. A document is one 1 MiB chunk plus the next 256 file bytes (§11.14's document row), so a term reaching further past a boundary is in no document, and likewise terms ANDed across two chunks. The 512 B query cap stays. SearchOracle evaluates each query per document as §11.14 defines it, not per file, and its query sets stay within the overlap.

Questions: `plan-SEARCH-small-readings.md#2`.

### QD-389: 5h's fence reads every bit-5 window entry's body, whatever its digest says
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Step 4 adds, in its one round, the statement and DROP body of every window version with bit 5 set, whatever its digest and whether or not it is above folded_through, from the process cache or a batch range. The fence reads the body only, never the lists. 5h tests each base, deleted path and reuse source against those bodies.

Changes: §11.8 step 4 (wording).

Questions: `plan-EVS2-small-readings.md#4`.

### QD-390: A DROP lists only versions with an entry hash, so removals below through_version are not listed
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

'every version below through_version' in §11.7's action row and §11.13's resolve row means the versions with an entry_sha256. A removal has none: it is never listed, never counted in EvsDropPath.count, and does not fail resolve's set equality.

Changes: §11.13 resolve row (wording).

Questions: `plan-EVS2-small-readings.md#1`.

### QD-391: A drop with any other not_before_ms is refused 409 DROP_STATE and fails readers' checks
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

evs refuses a drop (action 1) whose not_before_ms is neither time_ms + 604,800,000 nor time_ms with 409 DROP_STATE, recorded first by §11.8's refuse row. A cancel carries 0. Readers add the same equality to §11.7's states-row checks, and a failure raises history_drop in state invalid.

Changes: §11.7 refused row (wording); §11.7 states row (wording).

Questions: `plan-EVS2-small-readings.md#2`.

### QD-398: A replaced versionless version always exports as a pointer, whether or not its bytes survive
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Export writes every replaced versionless version as the git-lfs pointer to its content_sha256 and size, noted in refs/notes/ur, whether or not bytes survive in a store, batch or cache. Only a path's newest version exports its content.

Changes: §11.12 Export (wording).

Questions: `plan-EVS2-small-readings.md#7`.

### QD-399: FI-15 carries an overlay clause on a file-mode invariant
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

No code or model changes: only git-mode refs take overlays (11-EVS.md:390, :676), so in FI-15's scope the effective base version is base_version. Drop "effective" and ", an overlay's base counting its chain's base versions" at 22-TEST.md:877-878, so FI-15 reads as I-EVS-8 does. 5g's effective-base rule stays in §11.7.

Changes: FI-15 wording.

Questions: `g0-density-text-alignments.md#7`.

### QD-406: A manifest's shard figures go stale after a CLOSURE and are only bounds
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

After a CLOSURE, IndexShard.docs is an upper bound and first_day to last_day a covering range. No verify step compares them with a shard's header, and the next merge or roll-up recomputes them. An eraser still finds a document by a/m's days and the shard's doc table.

Questions: `plan-SEARCH-small-readings.md#4`.

### QD-408: `purge: observe` keeps staged content too, by writing it to seg/ at evacuation
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §19.*

While §19.11's purge is observe, evacuation treats a replaced staged segment as kept: it writes it to seg/<repo>/<id> before the batch's DELETE and logs it as a candidate. Reads still answer `collected`. The turn-on pass deletes it, as §11.13's sweep row says of what observe mode kept.

Changes: §11.13 staged row (wording).

Questions: `plan-EVS2-small-readings.md#6`.

### QD-409: A prune's 'commit of the last N days' counts a commit by committer date or its introducing push's time_ms
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A commit counts as 'of the last N days' at start s if its committer date or the time_ms of the first push that introduced it falls in [s - N days, s]. Either is enough, so a prune keeps the union.

Questions: `plan-EVS2-small-readings.md#9`.

### QD-415: §11.8's 1 MiB record bound counts a record's staged tail
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A record's 1 MiB bound counts everything in it, its staged tail included, so the push sender counts staged bytes against a part's bound. evs's purge list counts too: when listing candidates would pass 1 MiB, evs writes §11.13's existing mark instead, whatever the id count.

Changes: §11.13 purge row (wording).

Questions: `plan-EVS2-small-readings.md#13`.

### QD-416: A repo is always created at format 1, and a raise whose push fails leaves format 2 over format-1 data
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

PUT /evs/v1/repos/<id> always writes format 1. §11.6's raise, by If-Match on repo/ before step 7, is the only path to format 2, and a raise whose push then fails stands, since format-1 data is valid format 2. Nothing lowers it.

Questions: `plan-EVS2-small-readings.md#11`.

### QD-420: PageCpu and RemoteCpuPerMinute charge a compute slot's busy wall time
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

PageCpu and RemoteCpuPerMinute charge the busy wall time of a compute slot on the injected clock, summed across slots for RemoteCpuPerMinute. It over-counts under contention, so a page ends PARTIAL early and never late.

Questions: `plan-SEARCH-small-readings.md#5`.

### QD-426: 5c's VERSIONING is final from a repo kind, ref mode or creates-only ref, and recorded otherwise
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §19.*

VERSIONING from a config or mailcfg repo, a git-mode ref or a creates-only ref is final. VERSIONING from the lock, §19.11's gate or a DROP's versionless head is recorded before it is answered, since each can change. 5h's VERSIONING stays recorded, as the refuse row says.

Changes: §11.8 refuse row (wording).

Questions: `plan-EVS2-small-readings.md#3`.

### QD-428: Year-two DWPD labels pair the wrong figures in §11.20 and §19.9
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §19.*

§11.13's row holds: ~69 MiB/s is 3.3 DWPD on one set at ~5 records a batch, and 3.7-4.0 DWPD is a near-capacity set's ~1-1.6 records a batch. Make 11-EVS.md:3097 carry both pairs, and 19-OPS.md:552-553 read "3.3 DWPD on one set at ~5 records a batch, 3.7-4.0 (2.8-3.0) near capacity, five sets' worth".

Changes: §11.20; §19.9.

Questions: `g0-recheck-1-closed-item-text-errors.md#6`.

### QD-439: Numbers and carrier for §11.9's read states
*Proposed fill: a gap the agents filled; work builds on it.*

In evs.proto: enum EvsReadPathState { EVS_READ_PATH_STATE_UNSPECIFIED = 0; EVS_READ_PATH_COLLECTED = 1; EVS_READ_PATH_DROP_PENDING = 2; EVS_READ_PATH_DROPPED = 3; }, the state field of the per-path entry in EVS1-M2-01's EvsReadFrame, with the states' payloads (drop_id, not_before_ms, version) as ordinary fields of that entry. EVS2-M2-01 adds the three to testdata/evs/reserved_numbers.yml, and design-records writes them into §11.9. Format-1 code refuses each as FORMAT_UNSUPPORTED {needs_format: 2}.

Changes: §11.9.

Questions: `protos-services-read-states.md`.

### QD-443: How a canonical decoder takes a CLOSURE's pad on a slot or large entry
*Proposed fill: a gap the agents filled; work builds on it.*

Every index file carries IndexFileHeader.body_length, and everything after those bytes is pad, which must be all zero bytes, else index_malformed. A decoder accepts any such pad on any file type within the file's size bound, and re-encoding takes the pad length from the file. A writer's next head rewrite writes no pad.

Questions: `plan-SEARCH-index-format-bytes.md#6`.

### QD-444: VByte's encoding and the widths of the kind fields
*Proposed fill: a gap the agents filled; work builds on it.*

VByte is unsigned LEB128, as encoding/binary.AppendUvarint writes it: 7 bits a byte, least significant group first, the high bit set on every byte but the last, minimal, at most 10 bytes. An entry's kind, a row's doc kind and a tombstone's kind are one byte each: entry 1-4, doc kind 1 file, 2 mail, 3 record, 4 derived (SearchHit.doc_kind's values), tombstone 3-4. Any other value is non-canonical. doc_key and ref_id are 16 raw bytes.

Questions: `plan-SEARCH-index-format-bytes.md#1`.

### QD-460: Numbers for EvsHeadChanged
*Proposed fill: a gap the agents filled; work builds on it.*

As landed: EvsHeadChanged{ref_id = 1, version = 2, chain = 3, push_id = 4}, in PushHint.hint, version being the ref's while PushHint.version is the repo's push sequence. design-records writes them into §11.10.

Changes: §11.10.

Questions: `protos-services-unwritten-numbers.md#4`.

### QD-461: Enum values and the EvsRefusal code table
*Proposed fill: a gap the agents filled; work builds on it.*

ref_kind: 1 shared, 2 owned, 3 deposit, 4 erasure. EvsEntryVersion.kind and EvsName.kind: 1 file, 2 directory. Record kind: 1 checkpoint, 2 diff, 3 chunk. Batch record type: 1 push, 2 part, 3 seal, 4 reseed. repo/ kind: acl.proto's RepoKind, general 1 to secret 9. repo/ state: 1 keying, 2 active, 3 deleted, 4 shredding, 5 shredded. EvsRefusal.code is an EvsRefusalCode value, each with a fixed status: 1 SCOPE 403, 2 TIME_STALE 409, 3 REPO_KEYING 409, 4 REPO_DELETED 409, 5 QUOTA_PAYMENT 402, 6 QUOTA_LIMIT 403, 7 CLUSTER_FULL 507, 8 GATE_CLOSED 412, 9 INDEX_EPOCH 409, 10 MAP_PARTS 409, 11 EPOCH_SOURCES_FULL 412, 12 PATH_EPOCH_DUE 412, 13 DIRECTORY_FULL 409, 14 SEGMENT_GONE 409, 15 VERSIONING 409, 16 SLOT_UNKNOWN 409, 17 SLOT_STALE 409, 18 NOTHING_TO_ERASE 409, 19 DROPPED 409, 20 DROP_PATH 409, 21 DROP_CONSENT 409, 22 DROP_STATE 409, 23 DROP_BOUNDARY 409, 24 DROP_LIST 409, 25 FORMAT_UNSUPPORTED 409. QUOTA_LIMIT is 403 and never 429, since a 429 refuses nothing (§11.8). New names for §11.20: SCOPE, TIME_STALE, REPO_KEYING, REPO_DELETED, QUOTA_PAYMENT, QUOTA_LIMIT, MAP_PARTS, SLOT_UNKNOWN, FORMAT_UNSUPPORTED and, unrecorded, 5f's BASE_STALE.

Changes: §11.6; §11.8 refusal row; §11.20 push refusals.

Questions: `plan-EVS1-format-bytes.md#6`.

### QD-462: The encodings of repo/, place/, slot/, idx/, sealed fields and ids in keys
*Proposed fill: a gap the agents filled; work builds on it.*

Objects are proto3: EvsRepoObject {repo_id 1, kind 2, owner_member_id 3, state 4, state_ms 5, state_signer 6, deletion_id 7, format 8, sealed_name 9, network_id 10}; EvsRepoPlacement {cluster_id 1, creator_sidecar_id 2}; EvsSlotObject {keys 1} with EvsSlotKey {key_index 1, generation 2, wrapped 3}, an erased key leaving the list and no index shifting; EvsIndexEntry {versions 1, names 2, names_through 3, marker 4, drop_mark 5}. sealed_fields and sealed metadata are proto3 (EvsSealedFields {file_id 1, mode 2, git_oid 3, oid_kind 4, size 5, content_sha256 6}; EvsSealedMetadata), sealed as 24 B nonce | ciphertext | 16 B tag under manifest_g, AAD "UR evs 1.0 fields" or "UR evs 1.0 metadata" || repo_id || u64be(g). In object keys: repo, ref, slot and parcel ids are lowercase hex with no dashes, segment ids lowercase hex of 32 B, tokens 26 lowercase RFC 4648 base32 characters unpadded, and versions, epochs, page numbers and parts decimal zero-padded to 20 digits. The deepest idx/ key is 956 B, within §11.3's 1,024.

Changes: §11.6; §11.8 object table.

Questions: `plan-EVS1-format-bytes.md#9`.

### QD-473: The dictionary's offset bases, a bitset's bit order and N
*Proposed fill: a gap the agents filled; work builds on it.*

A block's two VByte offsets are absolute: its first entry's from the first byte after the block index, its first list's from the first byte of the postings. In a bitset, docid d is bit d & 7 (least significant first) of byte d >> 3, and unused high bits of the last byte are zero. N is the shard's live document count, IndexFileHeader.count, so ⌈N/8⌉ is that count's bitset.

Questions: `plan-SEARCH-index-format-bytes.md#4`.

### QD-474: Extractor 1's charsets and HTML stripping rules
*Proposed fill: a gap the agents filled; work builds on it.*

Charsets: a MIME part, RFC 2047 word or RFC 2231 value decodes through golang.org/x/text/encoding/htmlindex from the pinned module. No charset or an unknown label is treated as UTF-8, and invalid bytes go to U+FFFD at normalization. HTML: our own scanner on the decoded text, no parser library. <script> and <style> go with their content, up to the matching end tag, case-insensitive. Comments, <!...> and <?...> go. A tag is '<', then a letter or '/', to the next '>' outside quotes. A tag in the block list (address, article, aside, blockquote, br, center, dd, details, dialog, dir, div, dl, dt, fieldset, figcaption, figure, footer, form, h1-h6, header, hgroup, hr, li, main, menu, nav, ol, p, pre, section, summary, table, tbody, td, tfoot, th, thead, tr, ul) becomes one space; any other tag becomes nothing. Then entities decode by the standard library's html.UnescapeString, so '&lt;' stays text.

Questions: `plan-SEARCH-index-format-bytes.md#8`.

### QD-475: Spellings of <S>, <n>, <k>, L<seq> and a/<k>/ in index paths
*Proposed fill: a gap the agents filled; work builds on it.*

[plan-SEARCH-index-format-bytes#5] ASCII throughout. <S> is the bucket's start day as unpadded decimal. <n> is an unpadded decimal shard number from 0: a new shard takes the manifest's highest n plus 1, and joined shards keep the lower n. <k> in w/ is unpadded decimal 0-15, and L<seq> is 'L' and unpadded decimal seq. <writer> is the sidecar_id in lowercase hex and <h> its first two digits. Shards below n = 3,499 sit at a/<n>, and from there at a/<k>/<n> with k = (n - 3,499) / 1,000 rounded down, so no file moves and a/ holds at most 3,500 files with m. Directory numbers follow search-format-all-directory-names, which corrects k. [search-format-all-directory-names] Number the directories from where the files stop: k = 3,499 + (n - 3,499) / 1,000, rounded down, so shard 3,499 is `a/3499/3499` and shard 4,499 is `a/3500/4499`. This corrects plan-SEARCH-index-format-bytes#5's k from 0. Nothing moves at the split, and `a/` stays inside §11.7's 3,584 names until some 84,000 shards. `protocol/INDEX-FORMAT.md` and SEARCH-M10-05's path builder take this value of k.

Changes: §11.14 paths.

Questions: `plan-SEARCH-index-format-bytes.md#5`, `search-format-all-directory-names.md`.

### QD-476: A row's field order, and which field is cut when the caps exceed 2 KiB
*Proposed fill: a gap the agents filled; work builds on it.*

Row order: doc kind, flags, size, chunk, trigram count, started, expires, ref_id (ur/index only), locator, subject, from, to, title. File and mail rows stop there; record and derived rows then hold fields 6-15 in number order, each with its length, 0 when empty. Each field is first cut to its own cap (locator 512 B, subject, from, to and title 160 B, fields 6-15 256 B), setting flag bit 2+n for field n. If the row still passes 2,048 B, walk locator, then fields 1-4, then 6-15, each keeping what the 2,048 B leaves after the fixed part and the fields before it, cut on a code point, its flag bit set. Flag bit 18 is new: the locator is cut, or held a non-UTF-8 path mapped to U+FFFD, so it is not the exact path.

Questions: `plan-SEARCH-index-format-bytes.md#3`.

### QD-477: A slot's entry order, and where a replacing entry goes
*Proposed fill: a gap the agents filled; work builds on it.*

A slot's entries sort ascending by their 16-byte key (doc_key, or ref_id for a ref tombstone), then by kind, one entry a key. A replaced entry goes and its successor takes its sorted place, so a head is a function of its entry set and not of arrival order. Decoders refuse out-of-order or repeated keys.

Questions: `plan-SEARCH-index-format-bytes.md#2`.

### QD-506: Encoding and field names of planned route entries the design leaves unwritten
*Proposed fill: a gap the agents filled; work builds on it.*

An entry whose section states no encoding stays `application/octet-stream` with its fields in prose while it is `x-status: planned`, and the task that serves the route fixes the encoding when it lifts `planned`. Auth-key routes keep `duration_seconds`, `max_uses` and `bundle_still_admits` unless TEAM-M1-03 renames them in the same change. `POST .../path-epoch` takes §11.6's map row (`EvsPathMap` parts) as its body. `/path-epoch` and `/path-epoch/block` sit under `/evs/v1/repos/<id>/`, not under `/push/<push_id>/`, since a block names a ref and a map uploads before any push exists; design-records splits §11.20's line, which reads as if they hung off `/push/<push_id>/`.

Questions: `connect-m1-c11-route-scope.md#2`.

### QD-522: The HTTP bodies and the framed read reply
*Proposed fill: a gap the agents filled; work builds on it. Also amends §22.*

Bodies are proto3 messages in evs.proto, application/x-protobuf, except a segment PUT's raw bytes. EvsPushRequest {statement 1, payload 2, receipts 3, staged 4, part_places 5}: statement holds the Signed EvsPush bytes as received, and a seal sets part_places and no payload. EvsPartRequest {statement 1, part 2, receipts 3, staged 4}. EvsLeaseRequest {ref_id 1, base_version 2, ms 3}. EvsPushReply {version 1, place 2, deposit_head 3}. EvsRefusalReply {push_id 1, code 2, recorded 3, retry_after_ms 4, paths 5, outcome 6, needs_format 7, quota 8, deposit_head 9}. The read reply is a stream of u32 length | EvsReadFrame, each frame one of §11.9's parts by its set fields, with no oneof (§22.5's lint), ending in a frame with end true. Per-path state: enum EvsReadPathState {0 unspecified, 1 collected, 2 drop_pending, 3 dropped}, which joins the reservation lint.

Changes: §11.9 reply row; §11.20 API routes; D-PHASE-9's reservation list.

Questions: `plan-EVS1-format-bytes.md#8`.

### QD-523: Integer widths, byte order and payload framing
*Proposed fill: a gap the agents filled; work builds on it.*

All integers big-endian. Batch header, 32 B: "URpb" | format u8 | 3 zero bytes | instance u32 | minute u32 (minutes since the Unix epoch, UTC) | seq u32 | created_ms i64 | record_count u32. Record: type u8 | 3 zero bytes | repo_id 16 | ref_id 16 | push_id 16 | signer_sidecar_id 16 | time_ms i64 | length u32 | body. Index: offset u32 | length u32 per record, in record order. Trailer: index_offset u32 | SHA-256. EvsPlace, 20 B: minute, instance, seq, offset, length, each u32. EvsWindowEntry: §11.8's 64 B, paths_digest a u64 whose bit i is index i, flags a u32. EvsRefusal: §11.8's 16 B, code u16, until_s u32. Digest indexes: u32(h[0:4]) mod 64 and u32(h[4:8]) mod 64. Payload: sections of type u8 | length u32 | bytes, ascending, each at most once, absent when empty: 1 entry versions, 2 sealed metadata, 3 inline records, 4 change list, 5 part hashes, 6 new objects, 7 slot bodies, 8 erased list, 9 DROP body, 10 DROP lists, 11 tail moves, 12 source paths, 13 reuse list, 14 Merkle proofs. Repeated items in a section are u32 length | bytes, part hashes are bare 32 B values, and each *_sha256 statement field hashes its section's bytes. A new-objects item is kind u8 (1 segment, 2 staged segment, 3 slot) | id (32 B, a slot's 16 B) | padded_size u64 | upload_day u32 (days since the Unix epoch, 0 for staged and slots). Staged bytes follow the last section, outside every hash.

Changes: §11.6 payload row; §11.8 entry, refusal, digest and Batches rows.

Questions: `plan-EVS1-format-bytes.md#7`.

### QD-524: Where a general repo's wrapped object key sits
*Proposed fill: a gap the agents filled; work builds on it.*

In a general repo's kind-1 segment, a 72 B wrapped-key block sits at byte 32, right after the public header: 24 B nonce | 32 B object key sealed | 16 B tag, XChaCha20-Poly1305 under fek_g, g the header's generation, AAD "UR evs 1.0 object key" || repo_id || u64be(g). Records follow at byte 104. Format 2's kind-5 segment puts the same block at byte 48. For an inline chain, the same block opens the first inline record's EvsLocator.inline bytes, and the chain's later records use that key. A record reaches it through key_ref_kind 0 (#3). Slot-keyed repos and deposits have no block. The public header, padding and evs's checks do not change.

Changes: §11.6 segment and object key rows.

Questions: `plan-EVS1-format-bytes.md#2`.

### QD-525: The record header's field widths
*Proposed fill: a gap the agents filled; work builds on it.*

The 160 B header is 24 B nonce | 120 B sealed | 16 B tag, XChaCha20-Poly1305 under manifest_g (deposits: #5), g the segment header's generation or an inline record's push generation, AAD "UR evs 1.0 record" || repo_id || u64be(g). The 120 B, integers big-endian: record_id 16 | base_record_id 16 (zero unless a diff) | oid 32 | slot_id 16 (zero unless key_ref_kind 1) | generation 8 | body_length 8 | key_index 2 | kind 1 | key_ref_kind 1 (0 the container's own key, #2; 1 a slot) | oid_kind 1 (1 SHA-1, left-aligned and zero-filled; 2 SHA-256) | nonce_prefix 19.

Changes: §11.6 record row.

Questions: `plan-EVS1-format-bytes.md#3`.

### QD-562: dropscan/'s <f> spelling
*Proposed fill: a gap the agents filled; work builds on it.*

<f> is the kind (snap, cand, mark, del or held), a hyphen and a 10-digit zero-padded decimal sequence from 0: `mark-0000000042`. <id> is the job's or dry run's 16-byte id in lowercase hex. A checkpoint writes the next sequence, never overwrites.

Questions: `plan-EVS2-small-readings.md#12`.

### QD-568: Which devices prune, and when in the day each starts
*Proposed fill: a gap the agents filled; work builds on it.*

Any device holding every ref that may write ur/lfs prunes daily. Offset = u64be(SHA-256(sidecar_id || repo_id)[0:8]) mod 43,200 s. An unretired, unparked IndexerSet subject starts at 00:00 UTC plus its offset, any other such device at 12:00 UTC plus its offset, and a device asleep then runs at its next wake that UTC day. Any service list qualifies, since holding every ref is the real test.

Questions: `plan-EVS2-small-readings.md#10`.

### QD-575: TLC is on this machine
*Settled by the agents from the design; work builds on it.*

Done: the owner placed tla2tools.jar at ROOT/.stack/tools/. Run models with `tlc <track> [TLC args...] Spec.tla`, which refuses a jar with any other hash, and name revision d8fb231 wherever a TLC result is reported.

Questions: `plan-EVS1-tlc-tool.md`.

### QD-579: K_index_g's derivation context and how "pad" joins the hash input
*Settled by the agents from the design; work builds on it.*

K_index_g = HKDF-SHA256(RK_g, salt repo_id, info "UR evs 1.0 index" || u64be(g)), with no further context, g being the header's pad_generation. The pad's HMAC input is the 3 ASCII bytes "pad" then the 32-byte SHA-256 of the shard before its pad, || being plain concatenation.

Questions: `plan-SEARCH-index-format-bytes.md#7`.

<a id="s12"></a>
## §12 DNS

### QD-027: How internal services prove who they are
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §19, §7, §13.*

[plan-DNS-internal-route-credential] One bearer per caller class, the same scheme as plan-TLS-internal-credentials: 256 random bits in one vault file per caller (internal-dnsedge-1.yml, internal-dnsedge-2.yml, internal-monitor.yml, internal-monitor-outside.yml), each holding current and previous values so a rotation needs no downtime, read once at start from secret_files. The dns API block holds only their SHA-256, in internal-verify.yml, and compares in constant time. Each route takes only its class: dns edges on journal, snapshot, reload-diff and route-probes; the site monitor on canary and canary-report; the outside monitor on canary-report only. Every internal route moves under /dns/internal/, and the lb answers 403 there unless the source is in a new per-service allow list holding the site's ranges and the off-site monitor host's address, carried with W8. An edge needs neither the issuer nor Postgres to keep serving (D-DNS-3). [plan-TLS-internal-credentials] One bearer per caller class, as plan-DNS-internal-route-credential words it: internal-certs.yml in taskworker's secret_files and internal-lbmap.yml in the lb's, verified by hash on the dns API block. Each route takes only its class: certs on acme-challenge, caa-canary and ready; lbmap on custom-host-map and its applied route. lbmap sends its interface name in the request and the API checks it against the lb inventory. Do not build a per-interface secret: playbook-edges.yml copies the whole vault to every edge host, so it would isolate nothing, and §13.4 counts a report only once a dns edge's route probe of that version passes. POST /tls/suspend stays a model call inside api and taskworker, and its route is built only when a caller outside them exists. warp reads the file and sends a header, so it needs no JWT code.

Changes: §12.8; §19.4; §19.5 W8; §7.8; §13.15.

Questions: `plan-DNS-internal-route-credential.md`, `plan-TLS-internal-credentials.md`.

### QD-063: The DNS health check has no route or store
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §13.*

[plan-DNS-canary-route-state] Add two internal routes to §12.8. POST /dns/canary {root, value}, site monitor only: value is at most 64 printable ASCII bytes and starts with the writer's unix milliseconds; it writes canary.<root> TXT, TTL 60, through model.DnsWriteInTx (one serial, one journal row), answers {serial}, and answers 503 while restoring. POST /dns/canary-report {root, source, serial, ok}, source site or outside: ok is true only if the TXT validated through every running NS against the configured KSK anchor. Only the site copy of monitor writes; the outside copy reads, validates, checks the value is under 180 s old and reports, so no write credential leaves the site. Keep verdicts in a new table dns_canary_verdict(root, source, serial, ok, report_time), primary key (root, source), not in dns_root columns. Clean means the site row has ok true with report_time under 180 s old, and no outside row has ok false under 180 s old. A missing site row reads as failing. A stale outside row alone does not hold orders; it raises a visibility alert. No Redis family is added. [plan-TLS-canary-signal] GET /dns/ready?serial=s answers stale, ready or canary_failing, checked in that order: stale as today; while any running NS is below s it keeps holding; then canary_failing if plan-DNS-canary-route-state's clean rule fails, else ready. CertsDns.CanaryClean reads that answer. An order keeps waiting on canary_failing with no rewrite and no new serial, unlike stale, which writes again. A strong-mode CAA probe treats canary_failing as ready at both of its ready checks, because §13.8 ties the canary to orders only and the probe's RD=0 queries validate no DNSSEC. The delegated challenge route passes all three answers through.

Changes: §12.6; §12.8; §12.14; §2.8 dns-1; §13.8.

Questions: `plan-DNS-canary-route-state.md`, `plan-TLS-canary-signal.md`.

### QD-082: Record bookkeeping columns, and a suspended flag that cannot cover a host answered through *
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

network_dns_record gains create_time, expire_time and withheld_time, named in v9's dns-1, ttl with the record. Zone suspension (reason, until) sits on network_dns_zone. Do not use a suspended flag for hosts: use network_dns_host_suspension(network_id, host, create_time), and carry each row as a withheld owner in the journal and snapshots, which dnsedge answers NODATA for every qtype, so * no longer covers it. tlsedge and mxedge read the same rows. dns-1's store names the table.

Changes: §12.9; §12.14; §2.8 dns-1.

Questions: `plan-DNS-metadata-rows.md#5`.

### QD-124: What makes an NS running for /dns/ready and the restore step, and where a stopped NS is kept
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §19.*

A table dns_ns(root, ns, state, stopped_time, reason), state running or stopped, rows seeded from dns.yml. Running means state = running, whether or not the NS answers now. The restore step writes stopped; bringyourctl dns ns stop|start writes it by hand; an NS leaves stopped only once it serves at or above restore_serial. GET /dns/ready counts only running NS, and a running NS that does not answer keeps ready waiting. restoring clears once every running NS answers restore_serial. §19.8 pages only when both NS fail, so add a business-hours page when one running NS has failed SOA reads for 1 h, since orders are then held.

Changes: §12.6; §12.14; §2.8 dns-1; §19.8.

Questions: `plan-DNS-running-ns.md`.

### QD-147: Sidecars cannot read their label or zone, or file a label reclaim, on Network-class routes
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §13, §16, §19, §6, §7, §8.*

Add two routes to §12.8 on the dns block, both under §7.4's /dns/*. GET /dns/zone (service token, aud dns, any admitted sidecar of the network): the label, allocating on first need, the alias, the zone version, and this caller's view: the RRsets and custom-host states (state, CAA mode, readiness, pending interfaces) of owners on which it holds publish or admin on dns:<host>, by §8's gate. It is not the whole GET /network/dns body, which §12.8 keeps to read roles and §7.5 denies the Member role. POST /dns/label-reclaim (aud dns): the same tuple and signature as /network/dns/label-reclaim, with the token's network equal to the tuple's network_id. §16.5's dns_records maps to GET /dns/zone, and dns_set and dns_delete keep POST /dns/records. §13.4, §13.8 and §6.8's dns refetch read GET /dns/zone for sidecars, and §19.10's labels step names POST /dns/label-reclaim. /network/dns* stay for the console and network credentials.

Changes: §12.8; §13.4; §13.8; §16.5; §19.10; §6.8.

Questions: `plan-DNS-sidecar-zone-read.md`.

### QD-175: No route carries a delegated DNS-01 value from an ordering desktop to certs, and <token> is undefined
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §13, §7, §2, §8.*

Add network_domain.acme_token: 16 bytes from crypto/rand, lowercase base32 with no padding, minted by api when the domain first verifies (§7.6), fixed for the row's life, shown to admins in GET /network/dns as the CNAME target <acme_token>.acme.<root>. Add POST /tls/custom-challenge (service token, aud certs; the caller holds an active §8 publish grant on a host mapped under that domain; body {domain, value}, value the 43-character base64url DNS-01 digest) and GET /tls/custom-challenge/<id>. certs, still the only writer, writes the TXT through POST /dns/acme-challenge at <acme_token>.acme.<root>: at most 2 values, TTL 60, 10 per name per hour, gone after 1 h. The GET wraps /dns/ready with all its answers, stale and canary_failing included; the desktop asks the CA only on ready and posts the value again on stale. DNS-01 orders never wait on map readiness (§13.4).

Changes: §12.8; §13.15; §7.6; §2.8 api-3.

Questions: `plan-TLS-delegated-dns01.md`.

### QD-257: §12.6 raises a version it reads from a table the restore leaves empty
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

§12.6's step reads: raise the custom-host map's version 2^24 above max(every `network_dns_custom_host.map_version`, every version in `dns_custom_host_map_applied`, 0). Both tables are in the dump.

Changes: §12.6.

Questions: `xops-dump-short-ttl-list.md#3`.

<a id="s13"></a>
## §13 The TLS edge and certificates

### QD-107: ValidateListen must enforce verification and the publish time box
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §22, §21, §20.*

Add two rows to §13.9's ValidateListen table. network: no network_verified (§21.7). time box: a grant with no expires, or more remaining life than its cap, in a network at Community (7 d) or in probation or restricted state (24 h); Pro and Team may hold standing names. A network whose tier fell keeps a standing grant until §20.7's 14-day clock ends. The system publish keeps its own lines. An unknown fact refuses. Facts come through TlsListenFactsSource.

Changes: §13.9 ValidateListen; §22.5's §13 row.

Questions: `plan-TLS-small-readings.md#4`.

### QD-134: What a link audience's guest token is: one use on one device, or a shareable signed link
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §6.*

A link is a signed token, reusable until its grant ends. TlsLinkToken { bytes grant_id = 1; string host = 2; uint64 expire_time_millis = 3; bytes nonce = 4; } under SIGNED_TLS_LINK = 0x1503, purpose tls-link, signed by the publishing device's identity key, with expire_time_millis at most the grant's expires. The URL is https://<host>/.well-known/ur/link?t=<base64url(Signed)>. The front verifies the signature against the projection, that the signer is the sidecar the grant names, that grant_id is active and that host equals the SNI, then sets __Host-ur-link (HttpOnly, Secure, SameSite=Lax, 12 h, capped by the token's expiry) holding the same token, and answers 302 to / with Referrer-Policy: no-referrer. Any listener of the grant honors it with no shared state. GrantRevoke or expiry ends every link of the grant.

Changes: §13.7; §6.11 SignedType.

Questions: `plan-TLS-small-readings.md#8`.

### QD-188: No gate screens a published host
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §21.*

§13.9's `ValidateListen` table gains a row: `host ScreenName refuses it, or sends it to review without a screen_allow`. It screens on each registration through a short per-process cache of the verdict, its facts arriving on plan-SOCK-gate-data's surface, and TLS-M5-22 adds the call. A refusal at the gate needs no change to the signed `GrantActivate`, which api cannot rewrite.

Changes: §13.9; §21.6.

Questions: `plan-ABUSE-review-held-names.md#2`.

### QD-288: Where acmez and the CAA walk sit
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The CAA walk is pure code in the root behind TlsCaaResolver. For desktops, acmez and its resolver sit in cli/, injected as provers are, so neither reaches an sdk leg. certs keeps acmez on the engine leg (§13.8). dependencies.yml lists acmez for engine and cli only.

Questions: `plan-TLS-small-readings.md#17`.

### QD-294: ParseClientHello for mxedge
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

ReadClientHello, ParseClientHello, NormalizeSni and WriteTlsAlert export from tlsedgeservice, and server/mxedgehost passes them into MxEdgeDeps as functions, so no engine imports another.

Questions: `plan-TLS-small-readings.md#15`.

### QD-313: TlsEdgeOpen's 512 B bound against a long ALPN list
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

tlsedge keeps offered ids in hello order while the encoded TlsEdgeOpen stays at most 512 B, and passes that same list to Find. The listener decides from the real hello, so the field is informational. A hello whose only matching id was trimmed gets no listener, the closed direction.

Questions: `plan-TLS-small-readings.md#6`.

### QD-322: An unknown ALPN at Find, and the negative cache's key
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Keep internal_error when Find finds no listener for the offered ALPN, since no application byte moves and FS-34 holds; §13.7's no_application_protocol covers hellos that reach the front. The 30 s negative cache keys on (name, port, sorted offered ALPN set), so one scanner's bogus ALPN cannot refuse every visitor to a name.

Questions: `plan-TLS-small-readings.md#18`.

### QD-335: Drained interfaces in Route 53
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

warpctl dns reads sidecar.drained from config/<env>/sidecar.yml and leaves those interfaces out of the <env>-lb sets, keeping their health checks. One list drives Route 53 and the dns edges.

Questions: `plan-TLS-small-readings.md#16`.

### QD-339: `evs_unpaid_read_rate`
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

QUOTA-M2-10 owns it, as a per-process token bucket per network at `evs_unpaid_read_rate` divided by evs blocks, so the network stays at the published rate. The question's "up to N times the rate" misreads §13.9, whose caps divide by blocks to keep the total.

Questions: `plan-QUOTA-small-readings.md#8`.

### QD-344: Certificate rows lost in a restore
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §19, §9.*

The certificate manager compares GET /tls/certs with its local chain. A live local chain with no row re-orders: POST /tls/cert-order with a fresh attestation and replaces naming the old leaf's ARI id, so §13.8's limits skip it. replaces rides the request and no row stores it. ValidateListen keeps refusing until the new row exists. §19.10's 're-registers ... TLS endpoints' is this re-order followed by the §9 registration. An old certificate with no row may raise a CT alarm on a peer; that false alarm is the safe direction and stays.

Questions: `plan-TLS-small-readings.md#7`.

### QD-375: Route bodies for §13.15
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §2.*

TLS-M5-05 defines the JSON bodies of §13.15's routes from §13.8 and §2.8 cert-1. A stored field cert-1 lacks needs a row first (I-18). A request-only value, such as reading 7's replaces, is stored nowhere.

Questions: `plan-TLS-small-readings.md#3`.

### QD-376: Alerts for a killed name, a malformed hello and an unready edge
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A killed name answers unrecognized_name, as denied names do. A hello that does not parse answers decode_error. A cap, the gate being off or an unready map answers internal_error.

Questions: `plan-TLS-small-readings.md#5`.

### QD-377: Limits on tlsedge's inline path
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Limits load in the background through ServiceHost.Quota.Limits, cached per network. Until a network's limits arrive it gets Community's caps, never a refusal. The kill switch does not depend on this.

Questions: `plan-TLS-small-readings.md#11`.

### QD-492: TlsHint's body
*Proposed fill: a gap the agents filled; work builds on it.*

In protocol/tls.proto: message TlsHint { TlsHintKind kind = 1; bytes cert_id = 2; } and enum TlsHintKind { TLS_HINT_KIND_UNSPECIFIED = 0; TLS_HINT_ORDER = 1; TLS_HINT_ISSUED = 2; TLS_HINT_REVOKED = 3; }, the shape of SocketHint. cert_id is the 16-byte row id. The client refetches GET /tls/certs, so a hint is never authoritative.

Questions: `plan-TLS-small-readings.md#1`.

### QD-493: The tls-key attestation's body
*Proposed fill: a gap the agents filled; work builds on it.*

message TlsKeyAttestation { bytes network_id = 1; bytes sidecar_id = 2; bytes spki_sha256 = 3; bytes identifier_set_sha256 = 4; uint64 issue_time_millis = 5; } under SIGNED_TLS_KEY_ATTESTATION = 0x1501, purpose tls-key, signed by the device's identity key. identifier_set_sha256 is SHA-256 over the lowercase ASCII names, a wildcard written *.x, sorted bytewise, each followed by one 0x00 byte. SIGNED_TLS_EDGE_LOGIN = 0x1502, purpose edge-login, at M6.

Questions: `plan-TLS-small-readings.md#2`.

### QD-584: Where the PROXY listener lives
*Settled by the agents from the design; work builds on it.*

pires/go-proxyproto is on the engine leg, so tlsedgeservice.NewProxyHeaderListener holds it, server/cli/tlsedge applies it, and server/cli/mxedge may call it, since server may import both engines.

Questions: `plan-TLS-small-readings.md#14`.

<a id="s14"></a>
## §14 The SMTP edge

### QD-075: The intake cannot reach the network mail key, and a client-supplied mapping would let a member redirect sealed reports
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §15, §10, §7, §19.*

Not option 1's column. Which repo: a personal network's owner `mailbox`; a team's general repo whose signed `RepoCreate.inbox` is 2 (plan-MAIL-group-inbox); a scope's, its member's mailbox. api already verifies those rows, so `POST /mail/enable` takes no field and `mail_network` gains no column. Which key: api's gate read surface (plan-SOCK-gate-data's option 1) answers a network id with the newest GenRotate, fetched from gkm under a self-issued 15-minute `repo:<id>:deposit` token, aud gkm, through plan-KEYS-wire-gaps#8's `GET /gkm/repos/<id>/drop-key?since=<g>`, so no group id is stored. That scope reaches only this public-key read, and evs refuses the token. The intake seals only if g is the newest served, now is before `drop_not_after_ms`, and api's rows show g covers `holders_shrunk_at`, caching at most 5 min. Otherwise the raw bytes are dropped unread and the fields kept, which is every report before M7.

Changes: §14.8; §15.8; §10.14; §7.8; §19.4.

Questions: `plan-SMTP-report-seal-key.md`.

### QD-098: Where the TL4 allowance lives
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §15, §8, §2.*

Per recipient domain. A desktop keeps its approved allowance in `SidecarStore`. For a phone's message, the approved domains ride the signed `o/` entry (`tl4_domains`, plan-SMTP-wire-gaps#4) with the approval's id. A prover host honors them only if that entry's signature verifies and its signer is a consented device (§8.5) of the mailbox's owner, for that message only, and never copies them to its own store. Such mail keeps §2.8 EX4's label.

Changes: §14.4; §15.7 o/.

Questions: `plan-SMTP-small-readings.md#11`.

### QD-144: Re-proving Z1 in every part puts D-SMTP-16's m5.large bar out of reach
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Measure first on a real M1 and m5.large (SMTP-M9-32's `bench`) and keep D-SMTP-22 as written. If the miss is confirmed, relax the m5.large row of D-SMTP-16 rather than reopen the relation: the one hiding commitment saves about 1.4M of an estimated 6M to 7M constraints, and the m5.large budget is about 2.4M, so it cannot meet the bar alone and would add a new zero-knowledge argument to unaudited circuits. Set the new bar from the measured number.

Changes: D-SMTP-16; D-SMTP-22 (options 2 and 3 only).

Questions: `smtpproof-start-z1-reproof-cost.md`.

### QD-157: Mail report addresses use a hash nothing can reverse
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §12, §2.*

[plan-DNS-rua-token] network_dns_zone.report_token: 16 bytes from crypto/rand, lowercase base32 with no padding (26 characters), unique index, written in the zone's creating transaction, fixed for the network's life. _dmarc and _smtp._tls publish rua=mailto:<report_token>@rpt.bringyour.com in the label zone and its alias and scope zones. §14.6's nettoken becomes this value, with no key: Feedback-ID carries it through SmtpGate's cache, so the preamble path stays off Postgres. mxedge's platform listener maps token to network by the index. <root>'s _dmarc uses the fixed local part root, which no 26-character token can equal, and its rows split by header_from. [plan-SMTP-net-token] Option 1. `network_dns_zone.report_token`: 16 random octets, written at zone creation, shown as 26 lowercase base32 characters, unique-indexed, never rotated. It is `<token>` in `_dmarc` and `_smtp._tls` and `<nettoken>` in Feedback-ID. api and dns read the column; the intake finds a network by the index; `SmtpGate`'s cache carries it, so the preamble path stays off Postgres. 'Constant for burners' means a network's burners share its token, with no per-label value. `_dmarc.<root>`'s rua uses the fixed local part `root`, which no 26-character token can equal, and the intake splits those rows by header_from's `<net>` label, so burner domains that fall back to it still count once. §14.6 and smtp-2 read 'a random per-network token', and dns-1 gains the column.

Changes: §14.6; §12.7; §12.14; §2.8 dns-1; §2.8 mx-4; §2.8 smtp-2.

Questions: `plan-DNS-rua-token.md`, `plan-SMTP-net-token.md`.

### QD-187: A send's size is declared before its mode is known
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

[plan-SMTP-preamble-byte-count] Keep the one field. The sidecar declares the count for the expected mode: its pin's, else BDAT's unstuffed form. Issued headers have fixed lengths (plan-SMTP-small-readings#3 and #4), so every length is known first. After the post-TLS EHLO, if the mode that §14.4 selects cannot meet the declared count, the sidecar ends the connection before MAIL and reconnects once with the other count and `retry_of_send_id` set, costing a burst token and no unit (§14.7). A second mismatch is `deferred` on the retry schedule. This applies both ways, so an MX that offers CHUNKING gets BDAT, which corrects SPEC.md reading 14 and prover.go's 'a count only DATA can meet means DATA', since that can report a false `too_large`. [plan-SMTP-small-readings#3] `1.` then lowercase unpadded base32 of `key_id` (1 octet) ‖ `send_id` (12 random octets) ‖ HMAC-SHA256(key, send_id ‖ network_id (16 octets) ‖ day)[0:8], day a u32be count of UTC days since the Unix epoch: 21 octets, 34 characters, 36 in all. [plan-SMTP-small-readings#4] `<class>` is `n` for network mail or `b` for burners; `<tier>` is `c`, `p` or `t`; `<nettoken>` is 26 characters (plan-SMTP-net-token); the fourth field is `urnetwork`: 40 characters in all.

Changes: §14.5 SmtpPreamble; §14.6; smtpproof/SPEC.md 13.14.

Questions: `plan-SMTP-preamble-byte-count.md`, `plan-SMTP-small-readings.md#3`, `plan-SMTP-small-readings.md#4`.

### QD-191: `SmtpOutcome` has no message, no way past a cut, and no way to carry bounces that arrive later
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §6.*

`message SmtpOutcome { bytes send_id = 1; uint32 tls_level = 2; uint32 mode = 3; repeated uint32 reply_codes = 4; uint32 dsn_count = 5; uint32 hard_bounce_count = 6; bool downgrade_refused = 7; }`, 0x1603, a NO_REPLY envelope of type `SMTP_OUTCOME` to the ticket's listener, not an in-band frame. The edge accepts it from the connection's dialer for 15 min after the stream ends, then drops it. `dsn_count` and `hard_bounce_count` cover every DSN the sidecar made or received since its last accepted outcome, so bounces that arrive hours later ride the next send, and a sidecar that sends nothing more reports nothing. Self-report only, it only tightens, and it never feeds attribution.

Changes: §14.14; §14.4 step 5; §6.11 SMTP_OUTCOME's carrier comment; §14.8 Self-reports.

Questions: `plan-SMTP-wire-gaps.md#1`.

### QD-199: 'Over 10% hard bounces in 24 h' has no floor and no stored count
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §20, §2.*

New `sidecar_abuse:` keys `smtp_hard_bounce_percent: 10` and `smtp_hard_bounce_floor: 10`. The network halts when self-reported hard bounces pass 10% of recipients sent in the trailing 24 h and at least 10 recipients were sent, rates using recipients, not connections. `{smq_<networkId>}` gains 24 hourly bounce fields, 48 h expiry, added to smtp-4's sees.

Changes: §14.8 Self-reports; §20.4 sidecar_abuse; §2.8 smtp-4.

Questions: `plan-SMTP-small-readings.md#8`.

### QD-217: §14.4's 'retry, then DSN' has no schedule, and retries spend the daily unit
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

First retry at 30 min, doubling to 4 h, then every 4 h, with a DSN at 5 days. HALTED, QUOTA and TRY_LATER honor `retry_after_ms` and still end at 5 days. New `SmtpSenderSettings.RetryUnitsPerMessagePerDay`, default 2: a message's retries that reach MAIL spend at most 2 connection units a UTC day, and past that it waits for the next UTC day. This raises the question's 15 min to 30.

Changes: §14.4; §14.9 SmtpSender.

Questions: `plan-SMTP-small-readings.md#9`.

### QD-306: What a REQUIRETLS message needs
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A message flagged REQUIRETLS needs TL1 or TL2 and the post-TLS keyword. TL3 does not qualify, which narrows the question's 'TL1 to TL3'. Otherwise it ends before MAIL as `tls_refused`, and the DSN uses `5.7.30` for a missing keyword and `5.7.10` for missing TLS authentication.

Changes: §14.5 Outcomes.

Questions: `plan-SMTP-small-readings.md#12`.

### QD-310: E1-E3 and the dialog live in `smtpproof`, not the engine or `SmtpSender`
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

That split stands: `edgeSession` runs E1-E3 and `Prover` the dialog, through smtp_proof.go's seams. The engine keeps the gate, quota, MX, pre-TLS, splice, timers and send log, and `SmtpSender` everything around `SendSmtp`.

Questions: `plan-SMTP-small-readings.md#1`.

### QD-334: `dnssec_chain` must hold more than its comment says
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`dnssec_chain` carries every cut's DS and DNSKEY as well as the MX and TLSA RRsets with RRSIGs, in RFC 9102's order. The sidecar embeds every key in IANA's current root-anchors file, updated by release.

Changes: §14.5 field comment.

Questions: `plan-SMTP-small-readings.md#2`.

### QD-366: The gate's data
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`SmtpGate` answers from memory only, a miss answers TRY_LATER and starts a refresh, and its feed is what plan-SOCK-gate-data settles for every gate.

Questions: `plan-SMTP-small-readings.md#20`.

### QD-448: The frames ahead of raw TLS have no bytes
*Proposed fill: a gap the agents filled; work builds on it.*

Frames apply only to `SmtpPreamble` and `SmtpPreambleResult`: u32be body length ‖ u16be MessageType ‖ body, body at most 65,536 B. Raw TLS follows an OK result, and any other result ends the stream after its frame. A bad length or type resets with PROTOCOL. A `dnssec_chain` that would pass the bound is sent empty, so TL1 is not available on that connection.

Changes: §14.5.

Questions: `plan-SMTP-wire-gaps.md#3`.

### QD-449: §14.9's store has no DKIM key or recipient-count read
*Proposed fill: a gap the agents filled; work builds on it.*

The six `SmtpEdgeStore` methods stay verbatim, and a second interface, `SmtpReportLookups`, adds `FindDkimKey` and the recipient count.

Changes: §14.9.

Questions: `plan-SMTP-small-readings.md#17`.

### QD-452: Where an aggregate's sealed copy lives
*Proposed fill: a gap the agents filled; work builds on it.*

An aggregate gets a `smtp_complaint` row of type `rua` or `tlsrpt`, which counts as no complaint and feeds no halt, so `sealed_report` has a home. `smtp_dmarc_daily` keeps the counts.

Changes: §14.14.

Questions: `plan-SMTP-small-readings.md#14`.

### QD-487: No message carries TLS 1.3's disclosed SHTS
*Proposed fill: a gap the agents filled; work builds on it. Also amends §6.*

A new RPC: `message SmtpHandshake { bytes send_id = 1; bytes shts = 2; }`, `SMTP_HANDSHAKE = 0x1607`, sidecar to edge, sent as soon as the handshake ends, and `message SmtpHandshakeResult { uint32 code = 1; }`, `SMTP_HANDSHAKE_RESULT = 0x1608`: 1 OK, 2 INVALID, on which the edge ends the connection, 0 a protocol error. TLS 1.2 sends none. The edge forgets SHTS after E2 (D-SMTP-10). It needs `send_id` and a result, so two ids and two fields, not the question's one and one.

Changes: §14.5; §6.11.

Questions: `smtpproof-start-shts-wire.md`.

### QD-489: warp gives a block one fwmark
*Proposed fill: a gap the agents filled; work builds on it. Also amends §19.*

`smtpedge.yml` lists (address, HELO name, fwmark) tuples, the block's own mark being the default, and a host with several sending addresses needs W7 to add the other rules.

Changes: §14.9; §19.5 W7.

Questions: `plan-SMTP-small-readings.md#18`.

### QD-490: `SmtpStatus` has no message
*Proposed fill: a gap the agents filled; work builds on it. Also amends §6.*

`message SmtpStatus { uint32 kind = 1; uint32 retry_after_ms = 2; }`, 0x1604, in `PushHint.hint` on topic `mail`: 1 HALTED, 2 QUOTA, 3 CLEAR, 0 a protocol error (§6.11). No `label`, unlike the question's draft: the client reads a halt's scope from `GET /smtp/status`. smtpedge's halt job hints the clients with a send in the last 24 h, off the path; a client that misses it gets HALTED at its next preamble.

Changes: §14.14.

Questions: `plan-SMTP-wire-gaps.md#2`.

### QD-521: Selectors' form
*Proposed fill: a gap the agents filled; work builds on it.*

26 lowercase base32 characters from 16 random octets, one DNS label.

Changes: §14.6.

Questions: `plan-SMTP-small-readings.md#5`.

### QD-542: Which prover host takes an outbox entry
*Proposed fill: a gap the agents filled; work builds on it. Also amends §15, §22.*

Rendezvous hash of `effect_key` over the consented hosts in `p/`. The chosen host writes `or/<h>/<effect_key>` with outcome `queued` at the start and rewrites it at least every 5 min while the send runs. The next host takes over only after 10 min with no change to `or/`. A crash can still send twice, which §22.7 allows.

Changes: §14.5 Outcomes; §15.7 or/.

Questions: `plan-SMTP-small-readings.md#10`.

### QD-586: When `smtp_bytes_per_day` counts
*Settled by the agents from the design; work builds on it.*

It counts at close, so one message may pass it, and the next preamble's script answers QUOTA.

Questions: `plan-SMTP-small-readings.md#7`.

<a id="s15"></a>
## §15 The local email server, inbound mail, and burner email

### QD-025: Whether tracks may fetch mail modules through the Go module proxy
*Decided by the owner: owner 2026-11-08.*

Option 1: tracks fetch the Go modules the plan names through proxy.golang.org, checked against go.sum and the checksum database; each gets its dependencies.yml row with the license read from its files.

Changes: BRIEF.md tlc bullet.

Questions: `mail-m5-02-module-fetch.md`.

### QD-106: What `creator` means, who may change a record, and what happens when the creator is gone
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §8.*

`creator` is the sidecar_id whose signed push wrote the record's first version, and a reader checks the field against that push's signer. §8's `mail:<alias>#listen` is evaluated at the reader's current state for the creator's subject: an untagged sidecar's member, a tagged one's tags, read from its `SidecarRow`, which outlives the device. So removing a device leaves its addresses standing, and revoking the grant ends them. A later version of `addr/` or `burner/` (burn, pause, resume, members) counts only if signed by a consented device (§8.5) of the member who owns the record's mailbox, or for a group by a repo admin of the group repo; another signer's version is ignored with `mail_receiver_alarm`. 'Created only if absent' bars a second first version, not a state change. After a compromise revocation the owner's devices list the addresses that device created.

Changes: §15.7 mailcfg; §15.8 Address directory.

Questions: `plan-MAIL-small-readings.md#15`.

### QD-118: How the census reports per-ASN, by-volume SNI loss with no sender address kept
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Scripted census, the question's option 1, with the bar restated. A test network in main, dark (owner decision 91), takes mail one sender at a time: provider test accounts, ESPs and real sign-ups at the top-100 list. `sidecartest/mailcensus` joins each sender's window with the router's existing `urnetwork_mxedge_*` result counters and the test receiver's own view, one row per sender: sender, ASN, SNI, DANE, TLS version, plaintext fallback. The ASN column comes from the census's own sender list, never from `sender_ip` at the router, so mx-1, mx-2 and ops-1 stay as written. D-MAIL-9's 'by volume' cannot be measured this way, so the proposed bar becomes: the share of sign-up senders without SNI, each weighted 1/rank in the sign-up list, under 5%, shown beside the unweighted share. Report senders are listed but left out of the bar, because `rpt.bringyour.com` terminates every session, SNI or not (D-SMTP-19).

Changes: D-MAIL-9.

Questions: `plan-MAIL-census.md`.

### QD-189: §15.6's router has no way to name the lapsed receivers it must wake
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

No new route. `{mxr_<net>}`'s value gains `receiver_sidecar_ids`, at most 64, newest first, from `mail_host_key` rows for that host in state published, which `model.ProjectMailRoutes` writes on each key change. On a miss the router calls `Push.HintSidecars(ctx, ids, &ClientHint{Topic: "mail", Kind: 0x1702, Body: MailHint{RECEIVER_NEEDED, host}, Forced: true})` asynchronously, so the hold never waits on it and no Postgres query joins the path. The host resolves sidecars to clients as plan-KEYS-hint-addressing settles. The direct-MX alert is raised off the path by the prober, which reads the same ids from `mail_host_key`, since `{mxr_}` drops a direct-MX network. A device that misses either sees `direct_mx` in `GET /mail/status`.

Changes: §15.6 step 5; §15.15 {mxr_}.

Questions: `plan-MAIL-hints.md#2`.

### QD-196: A deposit's evidence exists only after the body, and §15.5 budgets the checks but not the upload
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §11.*

Keep `Deposit(name, reader)` and add no `BeginDeposit`. The sealed header goes last, inside the deposit's own stream: deposit plaintext = message bytes ‖ `MailDeposit` ‖ u32be(length of `MailDeposit`). The receiver's reader yields bytes from `mailSpool` as they arrive, blocks at the message's last byte until the checks finish, then yields the trailer, and EOF commits. Segments upload as they fill (8 MiB, §11.6), so a message under one segment uploads once, after the checks. To evs the trailer is body, sealed under the object key whose slot CONSUME and ERASE destroy, so it needs no K_dep and plan-EVS1-format-bytes#5's clause on §15.7's header drops. STREAM's final flag authenticates the tail, and a reader takes the trailer by ranged read before the body. The first repo streams live; a further repo, or a rebuild after 412 GATE_CLOSED, replays from the spool under a new object key and new slot ids, at most 4 at once, 2 on mobile. An aborted DATA ends the reader with an error, so no push commits and the uploads fall to §11.13's orphan rule. The spool stays sealed under a per-message key held only in memory.

Changes: §15.5 Session; §15.7 Deposit; plan-EVS1-format-bytes#5 (its §15.7 clause).

Questions: `plan-MAIL-deposit-shape.md`.

### QD-208: One failure across several repos, and the retry that repeats the others
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §20, §4.*

Any deposit failure answers `451 4.3.0`, and the sender's retry duplicates in repos that took it. To bound that: new `sidecar_abuse:` key `mail_inbound_repos_per_message: 8`. A RCPT that would add a ninth distinct repo gets `452 4.5.3`, and the sender sends those recipients in a later transaction (RFC 5321 §4.5.3.1.10). A group repo counts as one. `mail_inbound_recipients` stays 100.

Changes: §15.5 Session; §20.4 sidecar_abuse.

Questions: `plan-MAIL-small-readings.md#16`.

### QD-228: No risk row says a compromised receiver can forge reception-time verdicts
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

Add a §15.16 row: "A compromised admitted receiver seals passing verdicts for forged mail, which ingest, checking only the hash and the signer, labels validated | Low | High | per-device keys, I-15, Team scopes, listed mail indexers and the undesignated-receiver alarm (D-MAIL-15); the label states its basis, and any re-check shows apart (D-MAIL-14)". Add a §2.10 row: adversary, a compromised receiver; threat, reads mail in transit and seals forged verdicts; mitigation, those same controls; residual, what it sealed until revoked, since readers never re-judge reception-time evidence. D-MAIL-14 and D-MAIL-15 stand.

Changes: §15.16; §2.10.

Questions: `g0-recheck-0-receiver-evidence.md#2`.

### QD-243: Two roles cannot share one deployment service
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §19.*

[plan-MAIL-small-readings#19] Two warp services, `mxedge` and `mxedge-platform`, each a thin `server/cli/<dir>` over a shared `server/mxedgehost`, as OPS's reading 6. §15.15's Services line, §19.4's row, W4 and D-OPS-11's classes and §19.11's staged list name both. [plan-OPS-small-readings#6] `server/cli/dnsedge/` and `server/cli/mxedge-platform/` hold only a Makefile that builds the shared main and a Dockerfile that picks the role, so each plan's one binary stays one binary. W4 routes `rpt.bringyour.com`'s two interfaces to `mxedge-platform`. §19.4's mxedge row splits into two services, and §19.11's classes add `mxedge-platform` under `--only-older` and to the staged list after `mxedge`.

Changes: §15.15; §19.4; §19.5 W4; D-OPS-11; §19.11.

Questions: `plan-MAIL-small-readings.md#19`, `plan-OPS-small-readings.md#6`.

### QD-255: Per-network caps cannot answer 421, since the network is known only after STARTTLS's 220
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Per-sender caps (/64 or /32, with /48 and /24 aggregates) are checked at connect and answer `421 4.7.0` before TLS. '2 sessions per sender /24 per network' and 'per network' are checked once SNI names the network and close in the handshake, a temporary failure that writes `{mxc_}` like any closed handshake. §15.4's cap row says so.

Changes: §15.4 situation table.

Questions: `plan-MAIL-small-readings.md#1`.

### QD-262: §15.5 counts DohCache hits on a path that has no cache
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Option 1. §15.5 names MailDnsStub, a per-receiver cache in front of DohCache.Forward: answers kept by record TTL, at most 3,600 s; NXDOMAIN and NODATA for min(SOA minimum, 300 s), not at all without an SOA; never a failure, timeout or budget refusal; 4,096 entries, least recently used out; memory only. §15.5's dns row says "beyond stub hits" and AuthLimits.dns_queries's comment "stub hits excluded", with no field change. ext-3's "at most 64" stands.

Changes: §15.5 dns row; AuthLimits.dns_queries comment.

Questions: `g0-recheck-0-receiver-evidence.md#1`.

### QD-277: FS-123's last clause contradicts §15.9's and §18.5's coverage copy
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §18.*

FS-123's clause reads: GetReceiverCoverage's copy speaks of no sending, and every send copy names no indexer, receiver or coverage setting.

Changes: FS-123.

Questions: `plan-MAIL-small-readings.md#21`.

### QD-309: §15.10's `sent` copy is not in §15.7's layout
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A sent copy is an ordinary `m/` and `i/` entry with label `sent` in `f/`, pushed by the sending device.

Questions: `plan-MAIL-small-readings.md#9`.

### QD-329: A signature failing under a header section cut at 256 KiB
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

That signature is `incomplete`, not `fail`, and `limits.reason` sets bit 1.

Questions: `plan-MAIL-small-readings.md#12`.

### QD-332: mox answers permerror for any signature with `l=`
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Keep it: a signature with `l=` is `permerror`, so no result, refusing no mail.

Questions: `plan-MAIL-small-readings.md#11`.

### QD-333: `DmarcResult` has no permerror
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

An invalid DMARC record maps to `none`.

Questions: `plan-MAIL-small-readings.md#13`.

### QD-349: mox's `junk` does not fit `s/model`
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

MAIL-M7-12 builds a small per-mailbox naive Bayes filter of its own, kept in the one `s/model` file.

Questions: `plan-MAIL-mox-subset.md#2`.

### QD-352: A session with no network cannot leave a `mail_connection_record` row
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A session whose SNI is absent or unknown leaves no row and counts only in `urnetwork_mxedge_*`, which carries no network label.

Questions: `plan-MAIL-small-readings.md#3`.

### QD-353: `mail_operators.yml` with no YAML parser in the root
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`go generate` writes `mail_operators_gen.go` from the file, and `make check`'s stale-code rule keeps them equal.

Questions: `plan-MAIL-small-readings.md#18`.

### QD-370: Which EHLO is SPF's HELO identity
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

SPF's HELO check takes the post-TLS EHLO the receiver saw. `MailIngress.ehlo_name` stays the pre-TLS name.

Questions: `plan-MAIL-small-readings.md#14`.

### QD-405: Who raises `MailHint{deposit}`
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §18.*

Nobody. `deposit` stays reserved and is never sent. A new deposit reaches readers through evs's `evs:<repo_id>` hint and §18.7's wake, which covers topic `evs`.

Changes: §15.15.

Questions: `plan-MAIL-hints.md#1`.

### QD-432: Who fixes the bytes of the §15 formats the design names but does not define
*Proposed fill: a gap the agents filled; work builds on it. Also amends §6, §14.*

[plan-MAIL-format-bytes] Option 1. MAIL-M7-01 writes `protocol/mail.proto` and `protocol/MAIL-FORMAT.md`, pins them in `testdata/mail/` vectors, and `design-records` folds them into §15 for M7's Gn-in; nothing waits. Rows #1 to #7 give the values it uses. [plan-MAIL-format-bytes#1] In `protocol/mail.proto`: `message MailDeposit { uint32 version = 1; MailIngress ingress = 2; MailAuthEvidence evidence = 3; string mail_from = 4; bool require_tls = 5; repeated string recipients = 6; uint32 tls_version = 7; uint32 tls_suite = 8; bytes receiver_sidecar_id = 9; }`. `recipients` holds this repo's only. `tls_version` and `tls_suite` are the IANA values. A same-network deposit sets 1, 4 and 6 only, its signature being the deposit's EvsPush signer. It travels as plan-MAIL-deposit-shape's trailer, inside the body under the deposit's object key. [plan-MAIL-format-bytes#2] `message MailHint { uint32 kind = 1; string host = 2; }`, at most 256 B in `PushHint.hint`, with `PushHint.kind` 0x1702. `kind`: 1 DEPOSIT, reserved and never sent; 2 RECEIVER_NEEDED; 0 a protocol error (§6.11). `host` is `mx` or `mx.<scope>`. [plan-MAIL-format-bytes#4] Numbers follow §15.7's and §15.8's brace order; ids are 16-byte `bytes`, times `uint64` ms, enums have a zero UNSPECIFIED. `MailAddress`: kind 1 (1 admin, 2 id, 3 group, 4 agent, 5 burner, 6 bounce), mailbox 2 (repo id), members 3 (repeated), creator 4 (sidecar_id), effect_key 5. `MailBurner`: mailbox 1, state 2 (1 live, 2 paused, 3 burned), replying 3, created_ms 4, effect_key 5. `IndexEntry`: id 1, address 2, time_ms 3, from 4, subject 5, snippet 6 (at most 200 B), message_id 7, thread_key 8, size 9, attachments 10 (repeated {name 1, type 2, size 3}), auth_results 11, tls_label 12, tls_basis 13 ({rule 1: 1 requiretls, 2 operator; operator_id 2; list_version 3; strict_custom_mx 4}), spam_score 14, one_time_code 15. `VaultEntry`: entry_id 1, address 2, title 3, username 4, password 5, password_history 6, totp 7 ({secret 1, algorithm 2, digits 3, period 4}), urls 8, notes 9, used_at 10 (repeated {registrable_domain 1, first 2, last 3}), created 11, updated 12, state 13. `mailcfg` records take their signature from the version's EvsPush signer, so they need no SignedType. [plan-MAIL-format-bytes#5] One protobuf per file. `i/`: `MailIndexSegment{repeated IndexEntry entries = 1}`, at most 1 MiB or 4,096 entries, `<n>` decimal from 0 each month. `f/`: `MailFlagSegment{repeated MailFlagOp ops = 1}`, at most 4,096; `MailFlagOp{message_id 1, op 2 (1 seen, 2 flagged, 3 label, 4 trash), set 3, label 4, hlc_ms 5, hlc_count 6, sidecar_id 7}`. The clock: hlc_ms = max(wall ms, the highest hlc_ms seen), hlc_count 0 when wall time advanced it, else one more; last writer wins by (hlc_ms, hlc_count, sidecar_id) compared in that order. `r/`: `MailGroupRef{repo_id 1, message_id 2}`. `or/`: `MailOutcome{repeated SmtpDomainOutcome domains = 1}`, `SmtpDomainOutcome{domain 1, mode 2, byte_count 3, cap_byte_count 4, outcome 5 (1 sent, 2 queued, 3 deferred, 4 too_large, 5 refused, 6 tls_refused, 7 failed), reply_code 6, retry_after_ms 7, update_time_ms 8}`. `p/`: `MailProverRecord{data_proof_bytes 1, data_bytes_per_s 2, measure_time_ms 3}`. `forward`: `MailForward{address 1, burners 2, verified_time_ms 3}`, signed by its push. `ra/`: `MailReverseAlias{original_sender 1, burner_address 2}`. `s/model`: `MailSpamModel{version 1, counts 2}`, MAIL-M7-12 defining `counts`. `o/`: plan-SMTP-wire-gaps#4. [plan-MAIL-format-bytes#7] The router's builder holds `ip_listings` to at most 16 entries of at most 12 B, then, if the message still passes 1,024 B, drops `ptr_name` first and `ip_listings` from the end next. `version`, `sender_ip`, `sender_port`, `sni`, `ehlo_name` and `receive_time_millis` are never dropped. This reverses the question's order. [plan-SMTP-wire-gaps#4] `o/`: `u32be(length) ‖ Signed ‖ message bytes`. The `Signed` has `SIGNED_SMTP_OUTBOX = 0x1601`, purpose `smtp-outbox`, and its body is `SmtpOutboxEntry{effect_key 1, message_sha256 2, sender 3, recipients 4, flags 5, tl4_domains 6, create_time_ms 7}`. `or/` and `p/` are plan-MAIL-format-bytes#5's `MailOutcome` and `MailProverRecord`. [mail-proto-format-readings] Accept items 1 to 16 as landed in protocol/mail.proto, protocol/MAIL-FORMAT.md and testdata/mail/vectors.yml; design-records folds them into §15 with plan-MAIL-format-bytes. Item 2 adds `tls_level` to §14.5's MailOutcome. Item 3's `MAIL_TLS_MEMBER_SIGNED` is taken only if the push's signer may send as the From address. Item 9: MAIL-M7-16 decides whether a trash op's 30-day shred needs a guard against a slow device clock. [plan-MAIL-format-bytes#6] Nothing to do: `protocol/mail.proto` and `protocol/smtp.proto` exist on `sidecar`.

Changes: §15.7; §15.15; §15.8; §15.5 MailIngress; §6.11 SignedType; §14.5; §15.5; §15.7; §15.8.

Questions: `plan-MAIL-format-bytes.md`, `plan-MAIL-format-bytes.md#1`, `plan-MAIL-format-bytes.md#2`, `plan-MAIL-format-bytes.md#4`, `plan-MAIL-format-bytes.md#5`, `plan-MAIL-format-bytes.md#6`, `plan-MAIL-format-bytes.md#7`, `plan-SMTP-wire-gaps.md#4`, `mail-proto-format-readings.md`.

### QD-470: go-imap v2 has only pre-release tags
*Proposed fill: a gap the agents filled; work builds on it.*

Pin v2.0.0-beta.8, or a newer v2 tag if one exists when MAIL-M8-07 starts, with its `dependencies.yml` row saying it is a pre-release.

Changes: dependencies.yml.

Questions: `plan-MAIL-small-readings.md#20`.

### QD-478: `POST /mail/enable` and `GET /mail/status` have no bodies
*Proposed fill: a gap the agents filled; work builds on it.*

`POST /mail/enable` takes an empty body and returns `{enabled_time}`; plan-SMTP-report-seal-key adds no field. `GET /mail/status` returns `{enabled, storage_full, spent, direct_mx}`. A receiver reads status at most every 30 s for RCPT's `452 4.2.2`, and takes SIZE, `mail_inbound_recipients` and the burner limits from `GET /sidecar/limits`.

Changes: §15.15.

Questions: `plan-MAIL-small-readings.md#7`.

### QD-480: `{mxr_<net>}`'s key and value
*Proposed fill: a gap the agents filled; work builds on it.*

`<net>` is the SNI's routable part: a label, an alias or a custom MX host's full name. The value holds `network_id`, the host (`mx` or `mx.<scope>`), flags, and plan-MAIL-hints#2's `receiver_sidecar_ids`. A suspended network has no entry, so its SNI closes in the handshake.

Changes: §15.15.

Questions: `plan-MAIL-small-readings.md#4`.

### QD-535: SpfResult, DkimResult, DmarcResult, ArcResult and their verdict enums
*Proposed fill: a gap the agents filled; work builds on it.*

[protos-services-unwritten-numbers#5] As landed in mail.proto: verdict enums of 0 unspecified then §15.5's values in order; DmarcResult.alignment bits 1 SPF aligned, 2 DKIM aligned; ArcResult{cv, repeated ArcSet}, ArcSet{domain, selector, public_key}. MAIL-M7-01 may renumber until M7's Gn-in (plan-MAIL-format-bytes). [plan-MAIL-format-bytes#3] As landed in protocol/mail.proto on `sidecar`: `SpfResult`, `DkimResult`, `DmarcResult`, `ArcResult`, `ArcSet` and their verdict enums, 0 unspecified then §15.5's values in order, numbers open to review until M7's Gn-in.

Changes: §15.5.

Questions: `protos-services-unwritten-numbers.md#5`, `plan-MAIL-format-bytes.md#3`.

### QD-537: §15.4 fixes only one cap number
*Proposed fill: a gap the agents filled; work builds on it.*

`MxEdgeSettings` fields, set in `config/<env>/mxedge.yml`, tuned at T5: 8 sessions per sender /64 or /32, 32 per /48 or /24, 256 per network, and §15.4's 2 per sender /24 per network.

Changes: §15.4.

Questions: `plan-MAIL-small-readings.md#2`.

### QD-540: The platform listener's message cap
*Proposed fill: a gap the agents filled; work builds on it.*

`PlatformMessageByteCount`, default 16 MiB, advertised in SIZE; past it `552 5.3.4`.

Changes: §15.4.

Questions: `plan-MAIL-small-readings.md#17`.

### QD-541: Other pre-TLS commands have no reply
*Proposed fill: a gap the agents filled; work builds on it.*

Any other command before TLS (RSET, NOOP, VRFY, HELP and so on) gets `502 5.5.1`, within connect's 2,048 B and 510 B per line.

Changes: §15.4.

Questions: `plan-MAIL-small-readings.md#6`.

### QD-543: go-smtp's `LIMITS RCPTMAX` is not in §15.5's EHLO list
*Proposed fill: a gap the agents filled; work builds on it.*

Leave `MaxRecipients` 0 and enforce `mail_inbound_recipients` in `Session.Rcpt` with `452 4.5.3`.

Changes: §15.5 Session.

Questions: `plan-MAIL-small-readings.md#10`.

### QD-582: mox has no ARC
*Settled by the agents from the design; work builds on it.*

MAIL-M7-09 builds ARC in-house under §15.5's `arc` row, writing header canonicalization there since mox keeps its own unexported.

Questions: `plan-MAIL-mox-subset.md#1`.

<a id="s16"></a>
## §16 The local MCP server and record primitives

### QD-013: No path returns a non-grant ApprovalDecision to a deposit-only requester, or an admin's to a member
*Decided by the owner: owner 2026-11-06. Also amends §7, §8, §6, §2, §10.*

follow Proposed as the rule (the sealed ApprovalDelivery delta). (The recommendation it replaces: Add `ApprovalDelivery{header, requester_sidecar_id, sealed}`, a §7.9 delta with SignedType 0x1110, filed by the approver's device after it signs. `sealed` is the Signed ApprovalDecision or ApprovalCancel, HPKE-XWing to the requester's current ReaderKey (gkm/rk/<sidecar_id>, §10.5), so only the requester opens it, which is tighter than the question's sealing to the config generation. It counts against config_statements_per_day, adds one api-7 clause (signer, requester_sidecar_id, size) and authorizes nothing: the requester still runs §16.6's spend check. It serves tagged and ephemeral requesters, admin approvals of non-grant actions and §16.11's endorsement, so `filed_by` 3 keeps its meaning. Grants keep GrantActivate.)

Changes: §16.6 flow; §16.8 Approvals; §16.11 endorse; §7.9 records; §8.8 statements; §6.11 SignedType; §2.8 api-7.

Questions: `plan-RECORD-deposit-only-decisions.md`.

### QD-018: A forged SessionStart can leave a tainted run behind
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §5.*

Recommended: option 1, with its limit stated. The run file keeps the harness process's identity (pid and start time; local, never shown). Every session or event under a harness process binds to the union of that process's runs, ended ones included: a new run there starts with their taint, fsynced, until the process exits. Only a SessionStart reporting a fresh start opens a new run, a session with no live harness ancestor binds nothing and reads tainted, and SessionEnd clears nothing. §16.6's monotone row reads "a new run starts untainted unless a run of its harness process is tainted". FS-27 gains forged SessionStart and SessionEnd steps. §2.10 and §16.17 state the residual: a process that leaves the harness's tree (setsid, a launchd or systemd job, a second harness started detached) inherits nothing and can use what §5.5 leaves to any local process, so I-9 binds runs, not all of a user's processes (owner decision 47).

Changes: D-MCP-16; §16.6 monotone; §16.6 run file; §16.6 rejoin; FS-27; §2.10 P0 row; §16.17; RECORD.md section 4.3.

Questions: `plan-MCP-taint-new-session.md`.

### QD-041: How ur in a cloud VM gets its auth key, when setup is cached and environment variables reach the agent
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §5, §7.*

Recommended: a key file, never an environment variable. The environment's setup step writes the whole key string to a mode 0600 file, which the platform's snapshot keeps. The `--project` cloud profile's committed SessionStart hook runs `ur connect --token-file <path> --ephemeral` before any other `ur` step (a new flag beside `--token`): `ur` reads the file, enrolls, unlinks it and erases its copy, so the key is gone from the running VM before the agent's first turn. `ur` reads no key from any environment variable and refuses to enroll if `ur-authkey-` appears in its own environment. The key is a Delegation key with `max_admits` above 1 and §7.8's 30-day cloud `not_after`, because every session starts from the same snapshot; where a platform runs setup per session, a single-use key works and is preferred. Since a paused VM loses its processes, a cloud sidecar keeps its keychain in a 0600 file rather than memory, so a restored VM rejoins until its client is reaped (§7.7, 30-36 min); after that `ur` stays Unenrolled, capture spools, and a new session enrolls. §16.9 states the residual: anyone who uses the environment can read the key in its setup text, every snapshot holds it, and a copy admits fresh agents until the Delegation ends (§7.9).

Changes: §16.9; §5.6 ur connect row and Enrollment; §16.16 Provides.

Questions: `plan-MCP-cloud-auth-key.md`.

### QD-048: §16.10 fetches a hinted repo before phase 1, which contradicts D-EVS-50 and §2.8's promise for desktops
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §5, §2.*

Recommended: no fetch at search time. Hint coalescing becomes leading-edge: the first hint for a repo in a quiet Search.HintCoalesce interval fetches at once, and later hints in it wait for its end. A search reads only the cache. A version hinted but not fetched when a search starts counts as uncovered, so coverage reports it and it is never silently absent (FI-18). §16.10's sync row drops 'brought current before phase 1', and its Targets row reads 'a commit hinted before a search starts, unless inside a burst already coalescing, in that search's phase 1'.

Changes: §16.10 sync row; §16.10 Targets row; §5.4 HintCoalesce.

Questions: `plan-SEARCH-sync-before-search.md`.

### QD-064: Which CanonicalAction fields each server path may carry, and narrowing §16.8's "every field is sealed"
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §8, §2.*

§16.8 says "every field of an entry is sealed" and lists, per kind, what an action bound for a GrantActivate or a gate may set: kind, version, scope and the fields that path's gate sees. A grant: 8, 10, 11, 28, 29, and on a publish 5, 6, 7, 33 and 35. A version-3 access_request: 8, 10, 11, 14, 26, 27, 29. A `dns_*` action: 8 and 18-21. Whether a dial or route grant's prefixes and ports stay clear follows plan-BRIDGE-gate-row-prefixes.md#2, and this list follows that answer. api, every reader's GrantActivate check and each gate parse the stored bytes and refuse any other set field; MCP-M3-02's kind table gains that column. local_port, weight and alpn leave CanonicalAction (24, 25 and 34 become reserved, record.proto being unfrozen until M3) for sealed ApprovalRequest fields 14, 15 and 16, daemon-built and rendered by approvers (or `sealed_detail`, if that row's option is taken). `spendable`'s daemon side adds: d.request_sha256 = SHA-256(its stored ApprovalRequest), applying those values. Every O tool taking local_port binds it this way: socket_listen, tls_publish, bridge_forward and bridge_expose. api-10 gains kind, version, scope and the `dns_*` fields, api-7 gains kind, version and scope, and AD4 stands unchanged.

Changes: §16.6; §16.8; §8.8; §2.8 api-7; §2.8 api-10.

Questions: `protos-services-canonical-action.md`.

### QD-073: The list of allowed passkey origins does not exist
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §6.*

[protos-bridge-presence-gaps#2] One constant table in protocol/bridge/signed_presence.go. iOS, macOS, Windows and every CTAP client: https://ur.io. Android: android:apk-key-hash:<base64url SHA-256 of the release signing certificate>, a release input the owner supplies. VerifySigned and VerifyPresenceCountersign read the table and refuse any other origin, so only signCount stays with callers and §6.9's signature does not change. ecdsa-p256-sha256 has no origin. [plan-MCP-presence-origins#1] §16.6's webauthn-es256 per-use row gains this table, held in `webAuthnOrigins` in protocol/bridge/signed_presence.go, which `VerifySigned` and `VerifyPresenceCountersign` read, so every verifier refuses alike and §6.9's signature stays. `https://ur.io`: iOS passkeys, Windows Hello through the platform WebAuthn API, and FIDO keys over CTAP2, where `ur` builds client data and writes this value. `android:apk-key-hash:<unpadded base64url of SHA-256 of the signing certificate>`: Android passkeys. Exact match, no subdomains, no wildcard; option 2 is refused. The Android entry holds only the certificate that signs released builds: `mmm/ur.io/astro/public/.well-known/assetlinks.json` lists five fingerprints, and android/DEEP_LINKS.md says developer debug keys are among them, so copying that list would accept a debug-signed build. The owner names that one fingerprint, and the entry lands with M8's Android host, verifiers before the app, since the table is values in a release and no frozen format. Tests use fixture origins in testdata/.

Changes: §16.6; §6.9; §16.6 webauthn-es256 per use.

Questions: `protos-bridge-presence-gaps.md#2`, `plan-MCP-presence-origins.md#1`.

### QD-089: Under Padmé a private marker's entry is smaller than a full repo item, so evs can tell which new repos are private
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §11.*

Add `bytes pad = 14` (zero bytes) to `Announcement`. Every kind-repo announce entry, announcement or private marker, sets pad so the marshaled Announcement fills the next multiple of 2,048 B, which is exactly 2,048 B at every cap (a full item is under 1.2 KiB). Run and worker entries leave pad empty, and cards and r/ files keep their 2 KiB file steps. §16.11's caps row reads: entries by §11's Padmé, kind-repo announce entries at 2 KiB.

Changes: §16.11 Announcement; §16.11 caps row.

Questions: `plan-RECORD-m6-carrier.md#2`.

### QD-100: approval_use lacks the not_after that its retention and sweep are measured from
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §8.*

Add `not_after timestamp NOT NULL` to `approval_use`, holding the effective expiry the gate checked: the decision's `not_after_millis`, or the earliest under k approvers (§16.6's k approvers row). Every row carries it, done and cancelled alike. Add `CREATE INDEX approval_use_not_after ON approval_use (not_after)`. The taskworker sweep runs hourly and deletes rows where `not_after < now() - interval '1 day'`; it never reads `create_time`. Text edits: §16.6's `server` row gains the column. §2.8 api-10's `sees` reads "its index, effect key (...), state (done or cancelled), result, time and the decision's expiry", and its ttl reads "(ids, hashes, state, result and expiry only)". §8.10's sentence reads "`approval_use` only the approval id, use index, effect key, state, result and the decision's expiry". metadata_list.yml follows §2.8. The question's option 2 is refused: no 30-day ceiling exists to sweep by, since maxExpiry bounds grants and a rule may raise it (§8.6; acl.proto `AclRequestRule` field 8).

Changes: §16.6 server; §2.8 api-10; §8.10 gate paragraph.

Questions: `plan-MCP-approval-use-columns.md#1`.

### QD-103: Sealing whole harness files would taint every run, so the seal must cover what ur installed
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

§16.7's "sealing each file's hash" becomes "sealing a hash of `ur`'s entries in each file". The adapter extracts only what `ur` wrote. Claude Code: `mcpServers.ur` in `~/.claude.json` (`.mcp.json` with --project), and in `~/.claude/settings.json` (`.claude/settings.json` with --project) each `permissions.ask` rule and each hook entry whose command is this `ur`'s absolute path. Codex: `[mcp_servers.ur]` with its per-tool `approval_mode` in `~/.codex/config.toml`, and `ur`'s entries in `~/.codex/hooks.json`. Cursor: `mcpServers.ur` in `~/.cursor/mcp.json` and `ur`'s entries in `~/.cursor/hooks.json`. Each set is rendered as RFC 8785 canonical JSON (TOML parsed to the same form) and hashed with SHA-256, and the harness config hash, RECORD.md's `config_sha256`, is SHA-256 over the per-file hashes in that order: one rule for every file, no whole-file branch. The sealed value comes from `ur`'s own template at install, never from the file as found, so re-running `ur install-harness` restores entries and cannot bless a widened rule. The check at SessionStart and every 5 min compares a fresh extract and also counts as changed any other entry that can answer for a `ur` tool: a hook on PermissionRequest, PreToolUse or beforeMCPExecution whose matcher covers the `ur` server, or a `permissions.allow` rule naming it, in those files and, at SessionStart, in the project settings files of the session's working directory. An edit elsewhere in a file changes nothing.

Changes: §16.7 install paragraph; RECORD.md section 5.1 config_sha256.

Questions: `plan-MCP-config-hash-scope.md`.

### QD-104: An agent's evs_write can reach the harness config, and a synced change re-seals hook hashes
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Two edits. (1) §16.5's `evs_write` and `evs_delete` row, §16.6's refused list and D-MCP-17 add the vault's `harness/` path. (2) §16.7's "changes rewrite the local files and their hashes" is struck: the config holds no hook, ask rule or MCP entry, those come only from `ur install-harness`'s own template, and no synced change rewrites a harness file or re-seals a hash. A config value applies at each run's next SessionStart and is fixed for that session (D-CORE-18's rule): a narrower value at once, a wider one (`pii` from hash to off, a wider `claims`) only after the member confirms on /dev/tty or in an app, never through MCP. The next run's Coverage names the change.

Changes: §16.5 evs_write; §16.6 refused from MCP; §16.7 install paragraph; D-MCP-17.

Questions: `plan-MCP-harness-config-schema.md#2`.

### QD-105: Read literally, M6's fold lets any writer hide another's run by reusing its announcement_id
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

§16.11's M6 carrier row changes: run and worker items fold per (writer_sidecar_id, announcement_id), the highest (version, renewed_millis) within that writer. Only repo items fold across writers by announcement_id, ties going to the higher writer_sidecar_id bytes. Two writers on one run or worker id are two items: each shows under its own writer, neither voids the other, and readers raise record_alarm with reason id_reuse. Format 2's `a/ || announcement_id` document name takes the writer too, or a copied id shadows the real one in search.

Changes: §16.11 M6 carrier row; §16.11 documents row; FS-84's M6 case.

Questions: `plan-RECORD-small-readings.md#2`.

### QD-110: spendable never checks the SSHSIG that high risk requires
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Add to §16.6's `spendable`, after the evidence-list line: "and, where risk(a, P) is high, d.channel is device or presence and d.sshsig verifies (PROTOCOL.sshsig, namespace urnetwork-sidecar-approval, over RECORD.md section 5.1's bytes) under a KeyRow of d.approver_member_id with purpose sshsig, live at P". Under k approvers each decision carries its own. The verifier computes risk(a, P) from a and the matching rule and never reads ApprovalRequest.risk, since a gate holds no request. Gates run the same clause from `registered_keys`, and api-10 already lists SSHSIG as seen. The clause stands under any level set row #1 chooses, and goes only if SSHSIGs are dropped.

Changes: §16.6 spendable.

Questions: `plan-MCP-risk-classifier.md#3`.

### QD-115: How a sponsor or admin sets a tagged sidecar's worker announcement, when no record carries it
*Decided by the owner: owner 2026-11-06. Also amends §8.*

follow Proposed as the rule (deployment policy). (The recommendation it replaces: Read §16.11's "set by its sponsor or an admin" as whoever controls the deployment: `ur directory worker on|off` on the sidecar's own host, by hand or from the script that provisions it, stored in that sidecar's local settings, over `ServiceSettings.directory.workers`. No record and no reader check, and the table says so. To stop a running agent's item from elsewhere a sponsor uses Suspend or a revocation (§8.8).)

Changes: §16.11 Announcements table.

Questions: `plan-RECORD-worker-setting.md`.

### QD-116: Which harness config keys act, at which milestone, and what PII hashing means
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §8, §1.*

Recommended: two keys act. `record.redact.pii`, `off` or `hash`, default `hash`, from M3: email addresses and E.164 phone numbers become §16.7's marker with rule `pii-email` or `pii-phone`, each a redaction in the run's Coverage. `claims`, `{"default": auto|prompt|off, "projects": {<project key>: value}}`, from M6, read by CORE-M6-02 under D-CORE-18's rule. `agents.<label>` overrides those two keys only. `record.capture` is kept and ignored: capture stays §16.7's fixed set, since a narrowing control weakens R-MCP-4 and needs a person-only surface first. `reach`, `models` and `identity` are kept, ignored and warned about. §8.5's "a harness `reach:` block" files no request until a later design, and §8.5 and §1's row say so.

Changes: §16.7 Redact before seal; §16.7 install paragraph; §8.5 policy paragraph; §1 Global harness config row.

Questions: `plan-MCP-harness-config-schema.md#3`.

### QD-127: What P5:728's "a person approved a change" is, when approvals bind only outward actions
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

An `attestation` entry (kind 29, RECORD.md section 11): a person's signed statement (1 reviewed, 2 tested, 3 approved) about named commits, by `ur record attest` on /dev/tty or in an app's UI, with an SSHSIG where the member holds a key. It sits outside the I-8 gate, is never called an approval, and P5:728's copy says what it is.

Changes: RECORD.md sections 6.3, 11 and 17; Q-RECORD-7; P5:728 copy.

Questions: `record-md-change-approval.md`.

### QD-137: Which attestation roots a release may pin, given the FIDO metadata terms
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §23.*

Recommended: pin only roots their vendors publish, and no MDS data. Apple's WebAuthn root for `apple`, Google's hardware attestation roots for `android-key`, and a short hand-kept list of vendor roots for `packed` and `tpm`, in one data file a release step refreshes. §16.6's "FIDO MDS roots the release pins" becomes "the vendor roots the release pins". A statement that does not verify, or a format whose root is pinned and whose chain fails, is refused; a valid statement chaining to no pinned root labels asserted, as `fmt none` does. The label changes no authorization (§16.6's labels row), so a key outside the list loses only the word attested.

Changes: §16.6 webauthn-es256 registration; §23.7 Counsel.

Questions: `plan-MCP-presence-origins.md#2`.

### QD-138: Nothing in the design writes a `record` repo's entries
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

A log admin's `ledger_scope` entry (kind 43, RECORD.md section 6.5) names the repos and projects a ledger covers, and a sidecar with write on that log adds a copy of each T-bound run entry: T's projection, never a vault body. No tool changes and no agent chooses a log. `ur status` names each `record` log a daemon copies to, so a member can see it.

Changes: RECORD.md sections 6.3 and 6.5; §16.8 matrix; Q-RECORD-4.

Questions: `record-md-record-repo-writers.md`.

### QD-162: q/ has no shard level, and the question's fix fails too: `<h>` as the id's first two hex digits shards nothing
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §11, §15.*

Notices move to `q/<h>/<tgt>/<rid>`. `<h>` stops being the id's first two hex digits: in §16.11's `<h>` row for d/, r/ and q/, and in §11.14's `w/<h>/<writer>`, it becomes hex of SHA-256(the name it shards)[0], §15.7's shards rule, the name being `<sid>`, `<repo>`, `<tgt>` or `<writer>` as its path text. That gives 256 shards, about 917,000 targets. Approvers lease `q/<h>/<tgt>/`, and §16.11's rows 2 and 5 and §11.10's caps row name that prefix. No removal rule is added.

Changes: §16.11 ref cards table and `<h>` row; §16.11 Requests rows 2 and 5; §11.10 caps row; §11.14 paths row.

Questions: `plan-RECORD-notice-path-bound.md`.

### QD-166: M6's announce entries cannot express a withdrawal
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

`Announcement.state` gains 4 withdrawn, for kinds run and worker. A withdrawal is a newer announce entry from the item's writer at version + 1, holding only announcement_id, kind, version, renewed_millis, expires_millis, state 4 and who's member_id and sidecar_id. Readers fold it over the item at once and never show the item, as stale or ended. State 4 is terminal, so announcing again takes a new announcement_id. Repo items keep the private marker. §2.8 says that at M6 the earlier entries stay readable to every admitted sidecar until their 30 days or a directory admin's erasure, since a stream takes creates only.

Changes: §16.11 Announcement.state; §16.11 withdraw and M6 carrier rows; §2.8 team directory disclosure; FS-84's M6 case.

Questions: `plan-RECORD-m6-carrier.md#1`.

### QD-169: A stream's one-level e/ directory fills at about 7.3 million entries
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

The stream path is `e/<n div 4,194,304>/<(n div 2,048) mod 2,048>/<n>`, n a stream's own counter from 1, each part decimal, with section 20's vectors: 2,048 entries to a leaf and about 15 billion to a stream. In a stream that holds no ingested entry n equals seq, so `DecisionRef` still derives its path, and §16.11's DecisionRef comment says so.

Changes: RECORD.md section 5.2; §16.11 DecisionRef.

Questions: `plan-RECORD-stream-names.md#4`.

### QD-178: A pending socket request dies silently at rotation
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §9.*

[plan-RECORD-small-readings#15] §16.11's expire row gains this: at the first sync that shows a newer K_sock, the requester's daemon runs §16.11's cancel on each pending socket request (a decision entry with outcome cancelled, then the notice's removal, which frees both pending counts) and raises access_decided with outcome expired, and `ur directory requests` names the rotation. The person or agent files again under the new token, with a new endorsement where one is needed. [plan-RECORD-stream-names#3] A socket's `<tgt>` is 32 lowercase hex of SHA-256(name_token)[:16], name_token being §9.4's t_1 || ... || t_n as `RequestTarget.socket_token` holds it, never the raw token path. It changes when K_sock rotates; plan-RECORD-small-readings #15 says what follows.

Changes: §16.11 expire row; §16.11 ref cards table.

Questions: `plan-RECORD-small-readings.md#15`, `plan-RECORD-stream-names.md#3`.

### QD-203: §16.8's total order for a log cannot span its streams
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

§16.8's order row becomes: within one stream, (evs push version, position in the push), each push's entries sorted by (writer, seq); across a log's streams the verifiable log appends in batches, batch by batch, streams by ref_id bytes within a batch, each checkpoint entry listing its frontier and leaves; no log-wide sequence, no format change. RECORD.md section 10.1 stands as drafted. Land this before M3's Gn-in, not M6's entry as the question says, because D-MCP-6 freezes log order with the envelope.

Changes: §16.8 order row; D-MCP-6; Q-RECORD-1.

Questions: `record-md-log-order-across-streams.md`.

### QD-205: D-MCP-17 bars the evs tools from the config repo, while §16.6 refuses only reads
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §11, §7, §22.*

D-MCP-17 stands. Every evs tool and ur://evs resource refuses kind config, as for the team directory, and evs_repos alone names it. Align §16.6's refused list, §16.5's row, §11.12 (11-EVS.md:1417), §7.9 (07-TEAM.md:213, a copy the question missed) and §22.7's actions row. Agents use team_members, team_agents, acl_grants and acl_check.

Changes: §16.5; §16.6; §11.12; §7.9; §22.7.

Questions: `g0-recheck-2-mcp-config-read-scope.md#1`.

### QD-213: A presence prompt cannot finish inside ur hook's 300 ms
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Option 1. §16.7's How gains a second exception: on a host holding M's presence key, `ur hook` waits on a PermissionRequest (Cursor: `beforeMCPExecution`, the event `harness_ok` already pairs with it) for an O tool until the presence prompt ends, at most `Ingest.PresencePromptTimeout`, 60 s. Key signed: allow (`decision.behavior: allow`; Cursor `permission: allow`). Person refused: deny. Bound reached or prompt unavailable: no decision (Claude Code and Codex exit 0 with no output, the normal flow; Cursor `permission: ask`), and the O call then returns pending, so `ur approve` can finish it. Nothing is signed on refusal or timeout. `ur install-harness` writes `timeout: 75` on those hook entries, since Claude Code and Codex default to 600 s and Cursor states only a platform default. §16.6's presence prompt row names Cursor's event beside PermissionRequest. EXT-1 checks that an allow suppresses the harness's prompt under `permissions.ask`, since Claude Code says ask rules are still evaluated: if a prompt still shows, the person sees two and the key alone counts.

Changes: §16.7 How; §16.6 presence prompt.

Questions: `plan-MCP-presence-hook-timing.md`.

### QD-222: §16.9 and §2.18 understate a Delegation key's reach by omitting the team directory
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §10.*

A Delegation's reader key reads the config, a team network's directory and its tag repos (§10.5, §2.10). Change §16.9's "the config and its tags' repos" (16-MCP.md:671) and §2.18's "the config and tag repos" (02-TRUST.md:929) to say so.

Changes: §16.9; §2.18.

Questions: `g0-recheck-1-closed-item-text-errors.md#2`.

### QD-261: evidence_sha256 cannot hold the WebAuthn assertion that signs it
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

§16.8's comment becomes: harness: the matched hook event, which stays in the record; device and presence: empty, a presence decision's assertion riding in Signed.webauthn. Writers leave field 10 empty on channels 1 and 2. RECORD.md section 5.1 stands, and protocol/record.proto's copy of the comment follows.

Changes: §16.8 ApprovalDecision comment; protocol/record.proto comment; Q-RECORD-2.

Questions: `record-md-presence-evidence-sha256.md`.

### QD-269: I-EVS-14 lists a weaker signer test than §16.11's card row
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

A card's or notice's signer must pass §16.11's card row: admitted and not revoked, reaped, suspended or parked at the card's pin, and for a member device consented. I-EVS-14 (11-EVS.md:1101-1105) cites that row in place of "admitted and unrevoked". FI-25 (22-TEST.md:941), which the question missed, gains "unparked".

Changes: I-EVS-14; FI-25.

Questions: `g0-density-text-alignments.md#2`.

### QD-651: What bytes does `ur record open` write, and does a packet's `--content` take them?
*Decided by the owner on 2026-11-10, asked one question at a time.*

The file ur record open writes, and ur record disclose --content reads, is a new record.proto message, DisclosureOpenings {version, log_id, repeated Opening openings, repeated DisclosedKey keys, purpose}, which cannot be mistaken for a DisclosurePacket; the vault's disclosure entry of act 2 records its SHA-256 as packet_sha256. Adopted at M6's entry review: RECORD-M6-06's Open writes it and Disclose reads it (two functions), with a section 20 vector. RECORD.md section 11 names the message (design-records or RECORD's own doc).

Changes: RECORD follow-up at M6 entry review: DisclosureOpenings in record.proto, Open and Disclose, a vector; RECORD.md section 11 text.

Questions: `record-m6-05-open-file-format.md`.

### QD-298: The text of ids in paths
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Every id in a path is 32 lowercase hex characters, never `Id.String()`'s dashed form: `<sid>`, `<repo>`, `<rid>` and a repo or sidecar `<tgt>`. How `<h>` is derived changes separately, under plan-RECORD-notice-path-bound.

Questions: `plan-RECORD-stream-names.md#2`.

### QD-320: §16's list of agent UIs
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

§16's list is §16.5's two named UIs, MCP Inspector and OpenClaw. TLS-M5-23's tlsProbeTarget holds a small versioned table of their response fingerprints and refuses and records a match, plus the daemon's API and MCP ports.

Questions: `plan-TLS-small-readings.md#9`.

### QD-327: A request to a closed target is refused by the daemon and ignored by readers
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The daemon answers FAILED_PRECONDITION naming the target when its folded item says requests closed, or when it has no item and §16.11's `requests` row defaults it closed (group inboxes, owner-bound repos). Readers ignore a notice to a closed target, and raise record_alarm over_limit only if the request entry's push came over 1 h after the entry that closed it.

Questions: `plan-RECORD-small-readings.md#7`.

### QD-330: Directory tools outside a team network
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`directory_list`, `directory_requests` and `directory_request` stay in the catalog and answer FAILED_PRECONDITION naming a personal network, and `ur directory` prints the same and exits non-zero. A team network whose directory does not exist yet gets the same answer, naming that.

Questions: `plan-RECORD-small-readings.md#8`.

### QD-331: `--window` at M6
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

At M6 `ur admin directory --window` refuses with FORMAT_UNSUPPORTED {needs_format: 2} and signs nothing. `--keep` and `--searchable` work, since they set a RetentionPolicy.

Questions: `plan-RECORD-small-readings.md#14`.

### QD-355: A person's declared task has no writer in v1
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`AnnounceWho.harness` keeps the value `none`, readers accept and show such a run, and no tool, `ur` command or SDK call files one in v1.

Questions: `plan-RECORD-small-readings.md#5`.

### QD-360: The requester's record of an outcome is a `copy` entry
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The requester writes a `copy` entry (kind 39) to the member's vault, CopyBody holding one Opening (header, salt, body) per decision entry the notice names; a tagged requester deposits it to its sponsor's vault and writes none while it has no sponsor. RECORD.md's CopyBody comment and row 39's writer widen from "deposited to T" to cover it. As with every copy, an erasure of the decision in the directory does not reach it, and its prose stays a stub for agents.

Changes: RECORD.md sections 6.3 and 6.4.

Questions: `plan-RECORD-small-readings.md#6`.

### QD-388: §16.9 and Q-ACL-9 omit the cascade void from what drops a Delegation's key
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §10.*

§10.5 (10-KEYS.md:289) owns the list: DelegationRevoke, a revocation for any reason but reaped or a Suspend of one of its agents, a compromise revocation whose closure voids the Delegation, and not_after. Code follows it. Add "or a compromise revocation whose cascade voids it" to §16.9 (16-MCP.md:671) and Q-ACL-9 (08-ACL.md:472).

Changes: §16.9; Q-ACL-9.

Questions: `g0-recheck-1-closed-item-text-errors.md#1`.

### QD-412: Query limits apply where each is stated: the wire value at the indexer, the normalized one in each engine
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The indexer checks SearchRequest.query as sent, NFC as typed, at 512 B and 16 terms, answering INVALID past that. Each engine applies §16.10's limits to the normalized query. A wire-valid query that normalizes past the cap answers INVALID in the padded reply, and the phone falls back.

Questions: `plan-SEARCH-small-readings.md#7`.

### QD-445: The bytes of a P-256 presence key
*Proposed fill: a gap the agents filled; work builds on it.*

KeyRegister.public_key and KeyRow.public_key hold a SEC 1 uncompressed point, 65 bytes, for webauthn-es256 and ecdsa-p256-sha256 alike. A host converts a COSE key's x and y to it, and anything else is ErrSignedKey. KeyRegister.attestation keeps the raw attestation.

Changes: §16.6.

Questions: `protos-bridge-presence-gaps.md#1`.

### QD-503: A cancelled approval_use row has no effect key
*Proposed fill: a gap the agents filled; work builds on it.*

`effect_key` is nullable, with `CHECK (state = 'cancelled' OR effect_key IS NOT NULL)`. `POST /approval/cancel` inserts each use_index in 0 .. uses-1 that no row holds, with `state = 'cancelled'`, `effect_key` NULL, `result` NULL and the decision's `not_after`, each `ON CONFLICT DO NOTHING`. `UNIQUE (approval_id, effect_key)` stays: Postgres treats NULLs as distinct, so many cancelled rows fit, and a racing gate's insert conflicts on the primary key, finds no use left and answers 409 SPENT by step 2. No synthetic key.

Changes: §16.6 server.

Questions: `plan-MCP-approval-use-columns.md#2`.

### QD-513: The decider's journal row for a decision with no approval_id
*Proposed fill: a gap the agents filled; work builds on it.*

Append-only rows in `<state>/net/<network_id>/approvals/<request_id>`, file class `approval`, each fsynced before the step it guards: `Decide{request_id, step, payload, push_id, millis}`, step 1 intent (outcome, subject, expiry and note, before signing), 2 statement (the signed RepoGrant, EvsShare or ApprovalDecision; none for a denial), 3 entry (the signed decision entry), 4 notice (the version read and the rewrite). A restart resumes from the highest step with those bytes and push ids. For reach request_id is the approval_id, so the rows share that ledger file. §16.6's retention row, 30 d after not_after, outlasts §16.11's not_after + 1 d.

Questions: `plan-RECORD-small-readings.md#9`.

### QD-517: LocalSettings.RequestByteCount
*Proposed fill: a gap the agents filled; work builds on it.*

4 MiB. The bound holds a 1 MiB body at up to 4x escaping, not all-control-byte text at 6x. A line past it closes its session, and a hook event lost that way counts as §16.7's coverage gap.

Questions: `core-types-open-default-numbers.md#2`.

### QD-519: Mcp.SessionWriteRate.Burst
*Proposed fill: a gap the agents filled; work builds on it.*

20, a second's worth of §16.4's 20 W calls/s.

Questions: `core-types-open-default-numbers.md#6`.

### QD-520: Role and dial numbers
*Proposed fill: a gap the agents filled; work builds on it.*

`AnnounceWhat.roles`, and `DirectoryRequest.role` with a repo target, take acl.proto's RepoGrantRole: 1 deposit, 2 reader, 3 writer. With a sidecar or socket target `DirectoryRequest.role` is AclAction 1, dial. The target's kind says which, and 0 is refused.

Changes: §16.11 DirectoryRequest and AnnounceWhat comments.

Questions: `plan-RECORD-small-readings.md#4`.

### QD-529: Where the harness config lives and its file syntax
*Proposed fill: a gap the agents filled; work builds on it.*

One file, `harness/config.json`, on the `main` file-mode ref of the member's vault in each network: UTF-8 JSON, one object, `"version": 1`, at most 64 KiB, unknown keys kept verbatim on rewrite and ignored with a warning in `ur status`. A missing file means defaults. An unparsable file or an unknown version means defaults plus a `config_unreadable` coverage gap. A sidecar that cannot read the vault (tagged, cloud) uses defaults. JSON rather than the mock's YAML: `gopkg.in/yaml.v3` is on the test leg only (dependencies.yml), and this file is read and written on client legs (the redactor, `SetRuns`), where `encoding/json` adds no module.

Changes: §16.7 install paragraph.

Questions: `plan-MCP-harness-config-schema.md#1`.

### QD-549: The command that registers a member's SSH key
*Proposed fill: a gap the agents filled; work builds on it.*

`ur keys add-ssh <path>` reads one OpenSSH `ssh-ed25519` public key file, shows its fingerprint and signs `KeyRegister{alg: ssh-ed25519, purpose: sshsig}` under §16.6's `register` row: after a device or presence decision, never harness, as a /dev/tty-confirmed method refused from MCP. Any other key type is refused, and the private key never reaches `ur`. `ur keys ls` and `ur keys rm` already cover the key. §16.16's Provides adds the command.

Changes: §16.16 Provides.

Questions: `plan-MCP-risk-classifier.md#2`.

### QD-553: Several ports in CanonicalAction version 3
*Proposed fill: a gap the agents filled; work builds on it. Also amends §8.*

For a worker target `grant_dst` holds one string per port, `sidecar:<32 lowercase hex id>:tcp:<decimal port>`, ports ascending with no duplicates, an empty `RequestTarget.tcp_ports` expanding at filing to the worker's announced bridge ports, and `grant_allow` is ["dial"]. `target_port` is that port when there is exactly one, else 0. Approvers and §8.8's GrantActivate check refuse a version-3 action whose target_port is set and differs from its one grant_dst port. A socket target's string keeps its token path, as §8.4's rows do.

Changes: §16.8 CanonicalAction comment.

Questions: `plan-RECORD-small-readings.md#10`.

### QD-577: Where a member's per-project claims value lives
*Settled by the agents from the design; work builds on it.*

`ur directory runs` and `SetRuns` write `claims` into the harness config in the author's vault, per member and project, and CORE-M6-02 reads it at a session's start. Its file layout is plan-MCP-harness-config-schema's. A tagged sidecar, which reads no vault, takes the team default and `.ur`.

Questions: `plan-RECORD-small-readings.md#11`.

### QD-581: Product copy may not keep "per request" for model receipts
*Settled by the agents from the design; work builds on it.*

No. Per-request signing stays out of scope, and copy follows. At RS2 P5:779 says per grant and 5-minute window, with calls recorded per request from the harness at hook strength, and P5:766's "can prove" takes RECORD.md section 12's evidence labels. RECORD.md sections 12 and 17 stand, and no code changes.

Changes: P5:779 and P5:766 copy.

Questions: `record-md-model-receipt-granularity.md`.

### QD-585: Settings names: core-types' names stand, with RECORD.md's fields added
*Settled by the agents from the design; work builds on it.*

Keep `PushEntryCount`, `PushCoalesce`, `ReachReceiptCoalesce`, `CoverageIdleTimeout`, `TeamRecordKeepDays` and `TeamRecordSearchableDays`, and add RECORD.md section 18's other fields below them.

Questions: `plan-RECORD-small-readings.md#1`.

<a id="s19"></a>
## §19 Server services

### QD-021: M2 code names networks by label, but dns_label arrives with MG5
*Decided by the owner: owner 2026-11-06. Also amends §12, §23, §7, §9.*

follow Proposed as the rule (dns_label moves to MG2). (The recommendation it replaces: Move dns_label alone from MG5 to MG2, pending until M2's Gn-out, with model.EnsureNetworkLabelInTx, model.ResolveNetworkLabel and lazy allocation. The rest of dns_* and all DNS serving stay M5; aliases stay M6. Add GET /sidecar/label on api (Client class, sidecar-classified, so §7.4's /sidecar/* covers it): it answers {network_id, label, alias}, allocating on first need, and feeds DNS-M2-01's table. From M5 GET /dns/zone answers the same values. Draws before M5 run ValidateDnsName's reserved and brand rules from DNS-M0-01, which hold §12.5's list, curated brands included; ScreenName joins at M5 for later draws. <net> in .ur, git-remote-ur, §9.4 addresses and network:<net> then holds a real label from M2.)

Changes: §19.7 MG2 and MG5; §12.14; §12.16; §23.4 M2.

Questions: `plan-DNS-labels-before-m5.md`.

### QD-022: Who owns tls/current on an lb host, given that the vault copy writes through links and can destroy a JWT key
*Decided by the owner: owner 2026-11-06.*

stay on versioned paths for now. Nothing changes in production: no vault entry or lb image reads tls/current, W5's swap stays built but unused, and OPS-M5-07 builds against a test vault. This replaces Proposed. (The recommendation it replaces: Keep tls/current out of the vault entirely; hosts own the links. A new services.yml list, lb.tls_current: [<name>...], tells warpctl lb create-config which names read tls/current/<name>, and every other name keeps its newest versioned path, so the fallback per name stays. The builder refuses a vault that holds tls/current, so the write-through cannot start. warpctl certs swap <env> <version> moves the links on each lb host and reloads. It must also run with no lb up, to seed a new host or roll back, and must fail, not print Reloaded, when a running lb's config does not read tls/current or a listed name is missing from the version (the track review's two majors). playbook-edges.yml runs the swap right after its vault copy, so renewal stays one vault deploy, and xops/certs/renew.md gains that step. TLS-M6-01's lbmap keeps its own in-container reload.)

Changes: §19.5 W5; D-OPS-12; §19.11.

Questions: `warp-w5w6-tls-current-delivery.md`.

### QD-029: How exposed edge services reach data
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §13, §2, §12.*

[plan-TLS-edge-data-source] tlsedge reads Postgres, as §13.9 and tls-3 already have it. Its secret_files gain redis and a restricted Postgres role in its own vault file: SELECT on dns_label, network_dns_custom_host, network_tls_suspension and §12.9's suspensions, INSERT on tls_connection_record, nothing else. TlsEdgeStore is a background loop: a full snapshot at start, then model.DnsLabelMapSince every 5 s, so a withdrawn name stops mapping within 10 s. Kills still arrive within 5 s through {tes_} and reload every 60 s (§13.9). Records go in 10 s batches off the path. In a Postgres outage running processes keep their last snapshot, but a process started then stays not ready, so §19.10's 'edges run from Redis' reads 'run from memory and Redis; a restart waits for Postgres'. No connection path touches Postgres (I-12). [mx-foundation-router-store] Follow plan-TLS-edge-data-source, so the two edges match. Under its recommendation the router block gets a scoped Postgres role, used only from batch goroutines (I-12), and OPS-M7-01's "a router block takes no Postgres pool" is corrected, as plan-SMTP-report-intake-home also says. Separately, MAIL-M5-03 marks the platform role as needing no `MxEdgeStore`, so `Ready` waives it: it has no rows to write, and a stand-in store would prove nothing.

Changes: §19.4; §19.10; §13.5; §2.8 tls-1; §19.4; OPS-M7-01; MAIL-M5-03.

Questions: `plan-TLS-edge-data-source.md`, `mx-foundation-router-store.md`.

### QD-035: How the file cluster shows degraded-write debt, and how a set leaves `degraded` after a partial write
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Recommended, with one correction to the question: its option 1 is not available without a patch, because the admin API shows no partial-write queue at all. In the minio fork: er.addPartial sets SetIndex and PoolIndex (today it leaves them zero), and cmd/mrf.go exports, per pool and set, queue depth, a count of dropped entries and a count of unclean starts, since a crash loses the queue (only shutdown() saves it). monitor exports them as urnetwork_filecluster_mrf_depth{cluster,set}, urnetwork_filecluster_mrf_dropped_total{cluster,set} and urnetwork_filecluster_unclean_starts_total{cluster,set}. §19.6: `degraded` is entered on a drive or host offline or a depth above 0. It is left when a full heal ends with every drive online, or, if no drive or host was offline, when depth reaches 0 with no drop or unclean start since the last full heal. A drop or unclean start with every drive online raises a warn and starts one full heal. FS-40's DriveMiss phase holds healing, asserts `degraded` and depth 1 before nodes C and D go down, and adds a planted drop. Ledger S11's "Nothing" points at this row.

Changes: §19.6; §19.8; §19.10; FS-40; D-OPS-14; D-OPS-20.

Questions: `g0-recheck-1-s11-degraded-write-debt.md`.

### QD-040: How sockets authenticates a Client-class caller and learns its §8 subject with no Postgres and no by_jwt keys
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §5, §2, §9, §8.*

Keep Client class. Verify: sockets mounts a public-key export of the by_jwt keyring in `secret_files`, and session gains a verify-only keyring that rereads it as `byJwtKeyring` does. State: a new no-SQL check reads the revocation record alone: valid passes, a tombstone or rotation answers 401, Redis failure answers `unavailable`, and a miss answers `unavailable` with `retry_after_ms`, never SQL. A token with no root claim is refused. Grace: `{sc_<client_id>}ok` holds the last valid time, and a miss within 120 s of it counts as valid without moving it; a revocation in that span shows as a tombstone, which lives 10 min. This is needed because a client's positive field expires in 54-60 min and only a later check re-projects it, so connect's 60 s recheck leaves a gap of up to 60 s that would outlast a 45 s lease; the question's 'stays warm' is wrong there. Subject: `by_client_jwt` gains a `sidecar_id` claim; `POST /sidecar/bind`'s 200 adds a re-minted `by_client_jwt` beside `generation`, and refresh keeps the claim; a token without it is `denied` unless its network is `urnetwork-edge`. `revocation_record_enabled` must be on in production before M5. §19.10 and §19.17 then say sockets runs through about an hour of Postgres loss, since fields lapse and cannot be re-projected, after which it answers `unavailable`. sock-2 gains the sidecar id.

Changes: §19.4 sockets row; §19.10; §19.17; §5.15 bind reply; §2.8 sock-2; §9.8 {sc_}.

Questions: `plan-SOCK-client-auth.md`.

### QD-056: Nothing records that a cluster's running build passed FS-114, or its measured HDD capacity
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §22.*

Option 1. Add to config/<env>/sidecar.yml: file_clusters: {<cluster id>: {settle_passed_build: <commit>, hdd_capacity_ops: <n>}}, reread every 60 s as the file is. BlobCluster.SettlePassed is true only while every host's build in admin info equals settle_passed_build. An absent entry, an unreadable admin info or any mismatch reads false, so an upgrade reads false until the operator records the new build after filecluster-suite passes, and meanwhile no collection window opens and purges and drops delete nothing. hdd_capacity_ops is what §22.8's M3 hdd run measured, and {nvb_<cluster>} publishes it; while it is absent evs refuses no upload on HDD grounds and a drop job stays paused. Reword §19.6's settle and hdd rows and §19.11's yaml.

Changes: §19.11 sidecar.yml; §19.6 settle and hdd rows.

Questions: `plan-EVSB-settle-gate.md`.

### QD-076: What keeps api's public routes, the token exchange and CreateContract closed until §19.10's api step ends?
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Add `restore_hold: false` to §19.11's `sidecar.yml`. While it reads true, api answers every public route but its status route 503 with Retry-After 60, the token exchange answers the same, and connect's CreateContract answers `ContractError.Setup`. Open streams, sockets and edges are untouched, and §19.10's dns and api steps run as jobs behind the hold. The restore runbook's first step sets it, before the primary answers; the end of the api step clears it. A reader that cannot read the file keeps its last answer. FS-42 checks that a client revoked between the dumps gets no token or contract while it holds.

Changes: §19.10; §19.11; D-OPS-10; FS-42.

Questions: `plan-OPS-restore-hold.md`.

### QD-084: §19.9 narrows P0 against §11.13, D-EVS-33 and §7.9, and hold/, place/ and repo creation have no class
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §11, §7.*

Option 1. rev/, proj/ and projrows/ writes are all P0, kinds revocation and log. hold/ is P0, kind lifecycle. place/, a repo's creation writes (repo/, its first head) and activate's CAS are P1, queued per network by evs. Per-sidecar gkm/ stays P1. Reword §19.9's first row: 'their rev/, proj/, projrows/ and hold/ writes are §11.13's P0 and the rest queue per network'. Add projrows/ and hold/ to §11.13's classes row and D-EVS-33's list. api then needs no queue and only reports P0 bytes, as §7.9 says.

Changes: §19.9 first row; §11.13 classes row; D-EVS-33.

Questions: `plan-EVSB-write-classes.md`.

### QD-151: M5's report intake has no process or tables, since smtpedge and MG9 arrive at M9
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §14, §4, §15.*

Option 1. `SmtpReportIntake` runs in-process in the `mxedge-platform` block, as a library from `smtpedgeservice`, which server may import (§4.4). `smtp_complaint` and `smtp_dmarc_daily` move to MG5, and the rest of `smtp_*` stays in MG9. mxedge-platform takes a Postgres pool of 2 (§19.7's default). OPS-M7-01's 'a router block takes no Postgres pool' is a plan error to fix alongside: §15.4's 10 s `mail_connection_record` batches and §19.4's state column need one, off the connection path. Attribution and halts stay at M9 in the same package, once `smtp_send` exists. smtp-5's service reads 'mxedge (platform listener), then smtpedge'.

Changes: §19.7; §19.4; §2.8 smtp-5; §14.9; §14.14; D-SMTP-11.

Questions: `plan-SMTP-report-intake-home.md`.

### QD-163: warp cannot deploy one dnsedge service one host at a time
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §12.*

Two warp services, dnsedge-1 and dnsedge-2, each with one hosts: entry (ns1, ns2), one block, the same external_udp_ports and W9 TCP 53, and one image: server/cli/dnsedge builds it once and build/all/run.sh runs warpctl import <env> <image> --service_name=dnsedge-1 and -2, as it already does for manager to app (run.sh:3554). deploy-rollout.zsh lists both as single pass, dnsedge-1 first, and applies Q-OPS-5's stop rule (canary signature clean, NS serials equal) before dnsedge-2. dnsedge stays the role's name in §12 and the class name in §19.11. warp's core does not change.

Changes: §19.4 dns row; §19.11 Classes.

Questions: `warp-w5w6-dnsedge-one-host.md`.

### QD-182: §19.9's hdd trigger cannot be evaluated: no named series, no alert, unlike units
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §22, §23.*

Add to §19.8, published by §19.6's hdd loop, which already reads the counters, with no network or repo label: urnetwork_filecluster_hdd_drive_ops{cluster} and urnetwork_filecluster_hdd_capacity{cluster}, in drive operations a second, and urnetwork_filecluster_hdd_puts{cluster}, segment PUTs a second. Add resources hdd_ops and hdd_puts to urnetwork_filecluster_exhaustion_days{cluster,resource}. §19.9's trigger reads: the placement and the added capacity are ordered when monitor's 30-day trend of hdd_ops projects 50% of measured capacity, or its 30-day trend of hdd_puts projects §22.8's admitted throughput, within their lead time (§23.7), and land before it. §19.8's business row adds: a segment cluster whose projected hdd_ops or hdd_puts crossing falls within that lead time pages in business hours.

Changes: §19.8 metrics and business row; §19.9 hdd row; D-OPS-17.

Questions: `g0-recheck-0-hdd-trigger.md#1`.

### QD-214: FS-41 and FI-5 expect the close report to name an erasure §19.10 says it cannot
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §11.*

FI-5 and FS-41 follow §19.10's close row: the report names a repo that came back only under an EvsReseed as one where a lost ERASE may have returned keys, and never names the erasure. FI-5 reads "unless no surviving device holds the ERASE (§11.12's residual), which §19.10's close report flags by repo". FS-41 reads "with only stale mirrors, a repo that came back under an EvsReseed is flagged; with no reader pin above the mirror nothing names it, the stated residual".

Changes: FI-5; FS-41.

Questions: `g0-recheck-2-reseed-slot-keys.md#2`.

### QD-234: Which pager service does the rota use, and who owns the 30-minute escalation?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §23.*

A commercial pager service owns rotas, acknowledgment and the 30-minute escalation, reached from outside the site; the owner picks the vendor. `monitor` posts events with a dedup key through `pager.Sink`, a generic HTTPS event client, and page bodies hold class, time and opaque ids only, never a network name, address or token. A fake sink models the policy for FS-50 at T3, and the real policy is proved on the out-of-hours drill. §2.8 gains an ext row before it goes live (I-18).

Changes: §19.8; §2.8 ext rows; §23.7.

Questions: `plan-OPS-pager-service.md`.

### QD-236: Is there a canary environment to build for?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §22, §23.*

Build the cheap parts now: OPS-M2-05's `sidecar_pending` tag leg, a `config/canary/` a host could use, and `canary` kept in `sidecarPendingAllowed`. No plan counts a canary deploy as evidence, since T3 and M2's staging cluster prove stores and hosts. End state: drop the tier from §19.7, §19.11, §22.4 and §23.8 unless the owner buys hosts for it.

Changes: §19.7; §19.11; §22.4; §23.8; D-OPS-6; D-OPS-10.

Questions: `plan-OPS-canary-env.md`.

### QD-248: idx/ entries carry their state in object metadata, and only §19.6's MinIO row says otherwise
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §11.*

Option 1. Keep §11.6, §11.7, §11.8, §11.13 and evs-11. Reword §19.6's MinIO row to: objects carry content-type application/octet-stream and no user metadata, except an idx/ entry's state while its head lists sources (§11.7). The key is entry-state, the name blobsuite already uses, and its value is carried:<source epoch in decimal>, fresh or removed, read by HEAD; every other family carries none. A prefix check stays a HEAD, and no format changes.

Changes: §19.6 MinIO row.

Questions: `plan-EVS1-entry-state-metadata.md`.

### QD-249: §19.4's `secret_files` omit the metrics push credential every block needs
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

§19.4 gains one push-only vault file per service, `grafana-push-<service>.yml`, holding one user with the push role, in each new block's `secret_files`. `grafanaPushSettings` reads it first, then vault's `grafana.yml` for existing services. Never mount `grafana.yml` on a new block. Per service rather than the question's one shared file, so one compromised hostile-facing block's credential is revoked and rotated alone.

Changes: §19.4.

Questions: `plan-OPS-small-readings.md#5`.

### QD-252: §19.9's gen trigger has no input series
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §22.*

Add urnetwork_filecluster_gen_objects{cluster} to §19.8: a gauge EVSB-M2-12's nightly pass sets from its gen/ count, with no group or repo label, kept in monitor's 30-day trend beside the cluster's objects, and add resource gen_objects to urnetwork_filecluster_exhaustion_days{cluster,resource}, as g0-recheck-0-hdd-trigger.md#1 does for hdd. §19.9's gen row then reads: a warn when that trend projects gen/ past 10% of the cluster's objects within the next metadata cluster's lead time. §22.8's M2 count seeds the projection. The lead time's value follows g0-recheck-0-hdd-trigger's answer.

Changes: §19.8; §19.9.

Questions: `g0-recheck-2-gen-pack-trigger.md#1`.

### QD-260: A pack PUT must ride the streamed path, with an overall cap the question missed
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §11.*

Option 1, with a bound. pack/ PUTs are streamed PUTs: PutStream with the pack's SHA-256, no x-ur-deadline-ms, settle rule (2)'s 40 s after the last byte. taskworker cancels one whose last byte has not gone 8 min after issue, and the next run retries the pack. 5 s of cached repo/, 8 min and 40 s stay inside §11.12's 10 min phase 6. One pack per repo a run stands. Reword §19.6's deadline and settle rows, D-OPS-20 ('every request but a streamed segment or pack PUT'), §11.13's needs row and host_blobs.go's PutStream comment.

Changes: §19.6 deadline and settle rows; D-OPS-20; §11.13 needs row.

Questions: `plan-EVSB-pack-put.md`.

### QD-279: §19.6 and D-OPS-20 place a DELETE's copy in .trash, which a restart wipes
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Change "a DELETE's .trash copy" to "a DELETE's stash" in §19.6's settle rows and EVSB-M2-18's summary, with the sweep rule as built: the copy lives in `.minio.sys/settle`, which nothing wipes, and its sweep keeps it past a minimum age while any lock server or local write holds the key.

Changes: §19.6 settle rows (3), (4); D-OPS-20.

Questions: `minio-settle-stash-not-trash.md`.

### QD-639: Where does an evs process learn how many evs blocks serve, so evs_unpaid_read_rate divides by it?
*Decided by the owner on 2026-11-10, asked one question at a time. Also amends §13.*

evs takes a blocks count from config, as tlsedge does (§13.9, TLS reading 12): a key in config/<env>/sidecar.yml's evs gate block (or an evs settings file), set by the operator with services.yml's evs block count, which server/evshost passes as QuotaGateSettings.Read.Blocks. The read path keeps no shared state. The two built readings stand: a non-positive limit reads as unpaced, and FallbackRate (1 MiB/s split by blocks) paces until limits are read. An ops-lane follow-up wires it; §19.4's evs row names the key (design-records).

Changes: ops follow-up: evs blocks key in config/<env>/sidecar.yml and server/evshost passing it; §19.4 evs row (design-records).

Questions: `quota-m2-10-evs-block-count.md`.

### QD-285: W6's M0 deliverable is the recipe, and each service's task lands its own six artifacts
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

W6 at M0 means warp's README 'Adding a service' and warpctl/service_blocks_test.go. Each service's own task lands its Makefile, Dockerfile, lock entry, source graph, run.sh lines and rollout class at that service's milestone. A service joins staged_services only in the milestone its block lands (plan-OPS reading 12), since warpctl deploy panics with 'No matching blocks.' on a service with no blocks. Reword §19.11's Order step 1 to 'W6's recipe' at the next records pass. The README's steps 6 and 7 should also name build/all/deploy_rollout_test.go:204 and build/all/test_release_preflight.py:20, as the track review found.

Questions: `warp-w5w6-w6-ownership.md`.

### QD-297: §19.7 names RunRedisShardSubscription for the hint listener
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §6.*

§6.8 wins: publishers run on the exchange's shared keyEventSubscriber, whose SubscribeKeyEvents follows the master set. Replace §19.7's sentence (19-OPS.md:415) with "The hint listener rides §6.8's keyEventSubscriber, which re-reads the master set".

Changes: §19.7.

Questions: `plan-PROTO-small-readings.md#2`.

### QD-302: Per-block cluster credentials
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`file-clusters-<service>.yml` per block, read by EVSB-M2-02's `LoadFileClusters` in place of its one `file-clusters.yml`, each holding that block's MinIO user and policy.

Questions: `plan-OPS-small-readings.md#7`.

### QD-308: `{vault: no}` and `server.Vault`
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Every new block sets `env_vars: {WARP_VAULT_HOME: /srv/warp/secrets}`, so `Vault.RequireSimpleResource("redis.yml")` works unchanged, and Ansible makes each mounted file 65532:65532 mode 0400, as playbook-edges.yml does for grafana.yml.

Questions: `plan-OPS-small-readings.md#4`.

### QD-312: `ServiceHost.Tasks` outside taskworker
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`Tasks` is nil in evs and gkm processes, whose jobs run in taskworker and reschedule themselves. An engine that needs a job from a request path raises it as a question. KEYS-M2-17's `Tasks` holds only for the reconciler's registration in taskworker. host_tasks.go's "From any process" narrows to processes with Postgres.

Questions: `plan-OPS-small-readings.md#8`.

### QD-325: Readiness on a block with no Postgres
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`sidecarhost.Run` latches on `Engine.Ready()`; a block with Postgres also runs the shared check and its groups' markers.

Questions: `plan-OPS-small-readings.md#9`.

### QD-357: D-OPS-16's filter
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Load each dump into a scratch `redis-server` of the pinned version, delete the families, save, then compress, one node at a time, publishing nothing on any failure.

Questions: `plan-OPS-small-readings.md#13`.

### QD-362: The rollout stop
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A burn state monitor cannot read stops the step too, and an operator overrides by name.

Questions: `plan-OPS-small-readings.md#11`.

### QD-368: `cap_net_admin` for smtpedge
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Extend both allowlists, warp/services/load.go:167 and warp/warpctl/run.go:159, to smtpedge only, and set the capability on the binary in the image, so it still runs as 65532.

Questions: `plan-OPS-small-readings.md#14`.

### QD-371: The staged list grows
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Classes land at once, and each service joins `staged_services` in the milestone its block lands.

Questions: `plan-OPS-small-readings.md#12`.

### QD-380: W8's log shape
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`$request` becomes `"$request_method $uri $server_protocol"` by host, so each line keeps its three fields inside the quotes; hosts without sidecar routes keep `$request`.

Questions: `plan-OPS-small-readings.md#10`.

### QD-400: Front matter says `gen/` stays unpacked, where §19.14 gives it gen packs
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §10.*

§19.14 and §10.16 hold: gkm's gen/ takes gen packs at §19.9's gen trigger. Replace "`gen/` stays unpacked" at asm/data_front6.py:163 with "`gen/` takes §10.16's gen packs at §19.9's trigger", fix the comment at :144, and rebuild DESIGN.md.

Changes: front matter Q-OPS-2 row.

Questions: `g0-recheck-1-closed-item-text-errors.md#5`.

### QD-407: Whether rule (2)'s "metadata rename" reaches tagging, retention and self-copy
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Read "metadata rename" in §19.6's settle row (2) as RenameData with inline data, and say so in that row. UpdateMetadata and WriteMetadata carry no version and are not settled. They run under the key's write lock, take the clock rule and a 40 s deadline, and no sidecar service calls them.

Changes: §19.6 settle row (2).

Questions: `minio-settle-metadata-commits.md`.

### QD-411: Q-OPS-3's residual is closed in §19.14 and open in the front matter
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §23.*

It is closed: §19.14 owns Q-OPS-3 and reads "Residual: none", and §23.6's M0 row keeps D-OPS-18's closure as a gate. Drop the Q-OPS-3 clause from PEER_INTRO (asm/data_front7.py:123-125), leaving one residual. Add "Q-OPS-3's residual" to the ledger's section 5 beside Q-QUOTA-3's, keeping Appendix B's status as decided by the owner. Copy §19.6's bound into Q-OPS-3: <= 24 h plus the run (<= 20 min) at a primary's loss, <= 26 h at the site's, a day more per skipped or aborted run; and say "the dumped sidecar rows", since tables with a ttl of at most 7 d are in no dump. The "Closed by peer review 2026-11-04" label stays, as OT-N7's own row records that marking.

Changes: front matter PEER_INTRO; ledger section 5; Q-OPS-3 text.

Questions: `g0-recheck-2-q-ops-3-records.md`.

### QD-414: Three copies say "50% of rated IOPS" where §11.13 says rated write IOPS
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §22, §11.*

The limit is 50% of rated write IOPS (85k on the PM9A3), per §11.13 (11-EVS.md:1675), R-EVS-19 and D-EVS-33. Insert "write" at R-OPS-12 (19-OPS.md:22), 22-TEST.md:659, R-PHASE-11 (23-PHASE.md:21) and 19-OPS.md:279, a fourth copy the question missed.

Changes: R-OPS-12; R-PHASE-11; §19.6; §22.8.

Questions: `g0-density-text-alignments.md#5`.

### QD-421: Does `network_acl_share` join it?
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §2.*

[xops-dump-short-ttl-list#2] Yes. No dump holds it. An open invite is lost at a Postgres restore and is issued again. design-records adds its name to §19.6's list. [plan-DNS-metadata-rows#9] No decision needed. dns_label stays in api-2, where §2.8 has it. dns_custom_host_map stays out of every dump by §19.6's rule; add its name to the rule's 'today' parenthetical at the next records pass. [xops-dump-short-ttl-list#1] Yes. No dump holds it, as sidecar-tables.conf already marks. design-records adds its name to §19.6's list.

Changes: §19.6.

Questions: `plan-DNS-metadata-rows.md#9`, `xops-dump-short-ttl-list.md#1`, `xops-dump-short-ttl-list.md#2`.

### QD-458: taskworker reads each storage host's drive counters from a 5 s fluent-bit exporter on the storage LAN
*Proposed fill: a gap the agents filled; work builds on it.*

Option 1. On each storage host, a second fluent-bit pipeline beside the 15 s remote-write one: input node_exporter_metrics, scrape_interval 5, metrics diskstats; output prometheus_exporter on the host's storage-LAN address, port 2021, reachable only from taskworker hosts. The loop GETs http://<host>:2021/metrics every 5 s with a 2 s timeout through DriveCounterSource, reading node_disk_written_bytes_total and node_disk_writes_completed_total per metadata drive and node_disk_reads_completed_total and node_disk_writes_completed_total per HDD, the kernel counters of /sys/block/<dev>/stat fields 7, 5 and 1. A missing reading publishes nothing, as EVSB-M2-07 plans. SMART stays hourly on the textfile path, and remote-write to Mimir stays for monitor.

Changes: §19.6 counters row.

Questions: `plan-EVSB-counter-transport.md`.

### QD-481: `hash(network_id)`
*Proposed fill: a gap the agents filled; work builds on it.*

The first 8 bytes of SHA-256 over the id's 16 bytes, big-endian, mod 100, in one function every gate shares, EVS2-M10-05's `Format2Gate` included.

Changes: §19.11.

Questions: `plan-OPS-small-readings.md#2`.

### QD-495: tlsedge.yml's divisor for cap ÷ blocks
*Proposed fill: a gap the agents filled; work builds on it.*

tlsedge.yml gains blocks, a required integer of at least 1; tlsedge refuses to start without it. Its value is the number of lb hosts running tlsedge: each host's full-weight g1 block once, its beta block not at all, since §19.4's weights send 99% of a host's traffic to g1 and counting both would halve every endpoint cap. A process applies ceil(cap / blocks), at least 1, to concurrency and bandwidth; new-connection buckets stay per process.

Questions: `plan-TLS-small-readings.md#12`.

### QD-539: `p0_enforce` is in `sidecar.yml` and not in §19.11's list
*Proposed fill: a gap the agents filled; work builds on it.*

Keep `p0_enforce: {enabled: false}`, and add it to §19.11's list at the next records pass.

Changes: §19.11.

Questions: `plan-OPS-small-readings.md#3`.

### QD-574: How does a service block reach `vault/<env>/services.yml` when agents may not read vault?
*Settled by the agents from the design; work builds on it.*

The limit stands. Agents write each block as a fragment in `warp/services/sidecar-blocks/`, checked by warp's real loader on a synthetic base, and OPS-M2-03 builds `warpctl services apply-fragment`, which merges a fragment into the top version, allocates ports by warp's rules and prints a diff. The owner runs it against vault; that step stays on OPS's external list and each gate reports it open. No agent reads anything under vault.

Questions: `plan-OPS-vault-blocks.md`.

<a id="s20"></a>
## §20 Tiers, quotas, metering, and billing

### QD-020: Who writes a Team's next period, given `invoice.paid` arrives at least 72 h into it?
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

`RefreshTeamTransferBalances` writes each period's `team` grant and `team_credit` line at its 00:00:00 UTC anchor for every Team whose subscription is live with no unresolved payment failure. `invoice.paid` writes only the first period; on a cycle invoice it records the renewal's revenue, clears dunning and restores a line ended by a failure. `invoice.payment_failed` stops the next grant and ends the current line, so overage refuses at once while included bytes run out. §20.9 states what the job does. Exposure per unpaid Team is one period: its base, its seats and up to 10 TiB of line paid out at $3 per TiB.

Changes: §20.5; §20.9; D-QUOTA-8.

Questions: `plan-QUOTA-team-renewal-window.md`.

### QD-087: How does a lease's spent byte become a debit without counting twice?
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Carve. At each 60 s window the host runs one new branch of the reservation script that moves the window's used bytes, per balance in draw order, out of the lease's token into a token named for the journal row's `usage_id`, a no-op if that token exists. It sends (usage_id, balance_id, bytes) with the batch on the internal wire, so `UsageEvent` stays as engines see it. `ApplyUsageBatch` journals those rows, and the flush `release`s the token as it does a contract's. A killed edge's tokens lapse at 24 h with no debit, as FS-46 expects. No new table, column or Redis family.

Changes: §20.6; §20.14.

Questions: `plan-QUOTA-lease-debits.md`.

### QD-090: How is a day's transfer overage computed when four paths debit the line?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

`RollupServiceUsage` derives the row from the line, so every debit path feeds it and no settlement code changes. At each UTC day's close, take the network's `team_credit` balances ending within 7 d of that day, with used = start_balance_byte_count - balance_byte_count. The day's bytes are the sum of used now over yesterday's set and today's, less yesterday's stored total; store today's total over today's set. Keep C, the running sum of day's bytes, and write `team_transfer_overage` as round(C(d) / 2^30) - round(C(d-1) / 2^30), whole GiB, so rounding never accumulates. Both helper values are `network_service_usage` rows under meters `team_credit_window` and `team_credit_running`, which api-13 names and `GET /network/usage` hides. A debit counts on the day the pass first sees it.

Changes: §20.9; §2.8 api-13.

Questions: `plan-QUOTA-overage-accounting.md`.

### QD-094: What durable mark names a relayed contract, and how does it reserve with no added Postgres round trip?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

Set `payer_network_id` in the contract's one INSERT: no new column or statement, and payer plus no `transfer_escrow` row plus positive bytes names a relayed contract, since zero-escrow contracts set no payer. At close, read the payer's balances and each one's token before the close transaction. Teach `recoverRedisReservationWithFenceInTx` and `validateContractFreeSettlementOwnerInTx` that shape, and check every reader keyed on the payer (about 40 lines in server/model). Read credit from a per-process draw-order cache of 5 s. §20.6's cost row becomes "no Postgres round trip added on a warm cache, one read on a cold one", and connect-1 says the column is set here.

Changes: §20.6; §2.8 connect-1.

Questions: `plan-QUOTA-relayed-custody.md`.

### QD-143: "Active within 30 days"
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Recommended: a member is active if any client under its `member_id` has an `auth_time` within 30 days, stated in the billing terms, since an always-on device or a member's agent keeps that seat billed.

Questions: `plan-QUOTA-small-readings.md#11`.

### QD-164: §20.9's sites row and FS-46 omit three balance-order reads
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

All three follow `escrowDrawLess` behind `escrow_draw_order`. §20.9's sites row adds `deadlineEscrowRowsSql` (server/model/subscription_contract_scheduled_close.go:49-59), `proveRedisGrantExhaustion` (subscription_redis_exhaustion.go:179-185) and `zeroEscrowContractPriorityInTx` (subscription_zero_escrow.go:514). FS-46 adds a clause: a contract closed at its deadline keeps bytes on the pack before the line.

Changes: §20.9; FS-46.

Questions: `plan-QUOTA-draw-order-sites.md`.

### QD-180: evs bytes past every balance, and FI-13(a)'s "exactly once"
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

The rest of a debit overdrafts the last drawn in-window balance. With no in-window balance at all the bytes go unbilled, counted in `urnetwork_quota_unbilled_bytes_total`. FI-13(a) gains the exception: "barring an unclean producer exit, a batch dropped past its 10-min retry horizon, or a network with no in-window balance".

Changes: FI-13.

Questions: `plan-QUOTA-small-readings.md#5`.

### QD-295: The 14-day clock
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`NetworkDowngradeTime` is the end of the network's newest renewal of the tier it left.

Questions: `plan-QUOTA-small-readings.md#12`.

### QD-351: Nightly count against deltas
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The pass writes an absolute count, deltas landing during it are not replayed, and the next pass corrects them.

Questions: `plan-QUOTA-small-readings.md#6`.

### QD-356: `ReconcileSidecarCounters`
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The job recomputes `storage_over`, the connected set and spent marks, and reports row-counted capacities over their limits as a metric, refusing nothing.

Questions: `plan-QUOTA-small-readings.md#7`.

### QD-361: RESOURCE_EXHAUSTED over HTTP
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

HTTP 429 with the `QuotaRefusal` body and no Retry-After.

Questions: `plan-QUOTA-small-readings.md#13`.

### QD-430: Meter names
*Proposed fill: a gap the agents filled; work builds on it.*

`mx`, `smtp`, `evs`, `relay`, `team_transfer_overage` and `team_storage_overage`, beside the named `tls` and `team_seats`; the last two of the new ones and `team_seats` are also Stripe's `event_name`s.

Changes: §20.9; §20.14.

Questions: `plan-QUOTA-small-readings.md#2`.

### QD-488: `smtp_burst` holds one number for two windows
*Proposed fill: a gap the agents filled; work builds on it.*

New `pro.yml` key `smtp_burst_window`: 10 min on Community and Pro, 1 h on Team, beside `smtp_burst` 5, 50, 2,000.

Changes: §20.4.

Questions: `plan-SMTP-small-readings.md#6`.

### QD-491: §11.10's caps are §20.4 keys with no written names
*Proposed fill: a gap the agents filled; work builds on it. Also amends §11.*

Add to §20.4's sidecar_abuse: evs_subscribers_per_repo: 1000 and evs_repos_per_client: 500. The team directory's per-repo cap is the network's config_admissions instead, as §11.10 says. The per-repo cap counts distinct holders of {evsl_<repo_id>} inside the lease script. Past a cap the route answers a QuotaRefusal whose limit_key names the key, by §20.7's mapping.

Changes: §20.4 sidecar_abuse.

Questions: `plan-EVS1-subscription-caps.md#1`.

### QD-494: pro.yml keys for §13.9's per-visitor caps
*Proposed fill: a gap the agents filled; work builds on it. Also amends §13.*

sidecar_abuse: gains tls_visitor_concurrent: 64, tls_visitor_new_per_s: 20 and tls_visitor_aggregate_multiple: 4, the last applying to the /48 and /24 aggregates.

Changes: §20.4.

Questions: `plan-TLS-small-readings.md#10`.

### QD-496: The create cap's key and numbers
*Proposed fill: a gap the agents filled; work builds on it.*

`top_level_client_limit: 100` under each tier in pro.yml, read in place of `LimitTopLevelClientIdsPerNetwork`, with `network_top_level_client_limit` rows still overriding it.

Changes: §20.4.

Questions: `plan-QUOTA-sidecar-clients-store.md#2`.

### QD-510: Closure pacing's shape
*Proposed fill: a gap the agents filled; work builds on it.*

Each asking eraser holds one slot on a tail spaced 1/R apart. A refused upload keeps its slot, a taken turn takes a new slot at the tail, a slot lapses 5 minutes past its turn (setting `ClosureSlotHorizon`), and a per-second bucket of R still bounds the network when past-due erasers return together. §20.14's {sq_} row adds the tail.

Changes: §20.14.

Questions: `plan-QUOTA-small-readings.md#19`.

### QD-533: One lease per process
*Proposed fill: a gap the agents filled; work builds on it.*

`Quota.Lease` handles are ref-counted over one lease per process and (network, meter), and the last `Close` settles.

Questions: `plan-QUOTA-small-readings.md#16`.

### QD-538: `GET /network/usage`'s body
*Proposed fill: a gap the agents filled; work builds on it.*

`QuotaLimits`, `stored_byte_count`, `storage_over`, `spent`, and day rows `{usage_day, meter, quantity}` for up to 13 months, paged.

Changes: §20.14.

Questions: `plan-QUOTA-small-readings.md#10`.

### QD-544: The read-receipt budget counts through Quota.CountRate under two new keys
*Proposed fill: a gap the agents filled; work builds on it. Also amends §11.*

Add to sidecar_abuse: evs_read_receipts_per_repo_day: 256 and evs_read_receipt_bytes: 4kib. evs counts with ServiceHost.Quota.CountRate on the repo's network, key evs_read_receipts:<repo_id>:<UTC day>, debit id the push id, so a retry counts nothing twice. Past it: 429 with retry_after_ms to the next 00:00 UTC, as §11.12 says.

Changes: §20.4 sidecar_abuse.

Questions: `plan-EVS1-subscription-caps.md#3`.

### QD-546: Keys §20.4 only cites
*Proposed fill: a gap the agents filled; work builds on it. Also amends §12, §14, §11.*

QUOTA-M1-01's key table takes §12.7's `dns_changes_per_hour`, `dns_challenges_per_name_hour` and `dns_dkim_selectors`; plan-EVS1-subscription-caps' `evs_subscribers_per_repo` and `evs_repos_per_client`; plan-TLS-small-readings' `tls_visitor_concurrent` and `tls_visitor_new_per_s`; plan-SMTP-small-readings' `smtp_burst_window`; §14.7's breaker and destination numbers; and `evs_read_receipts_per_day` 256 a repo, from §11.12. Any area adds a key with one table row.

Changes: §20.4.

Questions: `plan-QUOTA-small-readings.md#1`.

### QD-547: §14.7's concurrency cap has no number
*Proposed fill: a gap the agents filled; work builds on it. Also amends §14.*

`smtp_destination_concurrency: 10` in `sidecar_abuse:`, per (sending address, destination /24), in edge memory; tune on M9's first runs.

Changes: §20.4 sidecar_abuse.

Questions: `plan-SMTP-shared-counters.md#3`.

### QD-548: Leaving spent
*Proposed fill: a gap the agents filled; work builds on it.*

A taskworker pass every 60 s, a setting, clears `spent_time` once any in-window balance has room, so a new grant reopens a network within about a minute.

Changes: §20.6.

Questions: `plan-QUOTA-small-readings.md#4`.

### QD-551: Team's names
*Proposed fill: a gap the agents filled; work builds on it.*

`SubscriptionTypeTeam` ("team") in `subscription_renewal`, and grant kinds `team` and `team_credit`, both added to `grantGrace`. The credit line carries `pro=false` and no `tier`, so it never confers the tier.

Changes: §20.5.

Questions: `plan-QUOTA-small-readings.md#15`.

### QD-552: `usage_id`
*Proposed fill: a gap the agents filled; work builds on it.*

A relayed row's `usage_id` is its `contract_id`; a batch row's is the first 16 B of SHA-256(batch_id || network_id || meter || balance_id).

Changes: §20.14.

Questions: `plan-QUOTA-small-readings.md#3`.

<a id="s21"></a>
## §21 Abuse, safety, and legal process

### QD-006: A stranger's report of CSAM or a threat to life can wait 7 days on Community
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Recommended: add both categories to §21.8's fourth row, 4 business hours on every tier, with one line in `AbuseSignalOfReport`, and ask counsel whether the weekend gap is acceptable. The pager stays as owner decision 134 set it.

Changes: §21.8.

Questions: `abuse-core-urgent-report-clock.md`.

### QD-008: Under a hold, does a user's network or client deletion delete the rows the hold covers?
*Decided by the owner: owner 2026-11-06. Also amends §2.*

follow Proposed as the rule (silent deferral). (The recommendation it replaces: Silent deferral. `RemoveNetwork` and `RemoveNetworkClient` on a held network read as done to the user, and in the deletion's own transaction copy the in-scope rows they delete (api-1, api-4, api-5, `network_acl_head`) into the hold's `copied_rows`. No refusal, hint or admin event. The repo shreds a deletion starts still run under owner decision 133. The idle client reaper is a TTL sweep, so it skips held rows. api-14 and §21.9 say so, and counsel sees it beside owner decision 133's condition.)

Changes: §21.9; §2.8 api-14; R-ABUSE-5.

Questions: `plan-ABUSE-hold-deletions.md#1`.

### QD-026: What values does a hold's `scope` take?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §11, §2.*

`scope` is the string `network`, or a list of 1 to 16 repo ids. A repo scope covers that repo's objects on every cluster and its gkm group. Server rows (tls-3, mx-2, smtp-3, api rows) are always covered by network. Counsel sets the scope from the order, defaulting to `network`. Scopes compare by containment: a repo stays until the latest `expire_time` of any hold that covers it. Readers treat an unknown or unparsed scope as the whole network.

Changes: §21.9; §11.8; §2.8 api-14; §2.8 evs-19.

Questions: `plan-ABUSE-hold-format.md#1`.

### QD-033: When strikes add up to suspending a network
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §14, §23.*

Recommended: accept items 3, 5 and 7 as landed. Item 3: "3 halts" counts the network's `mail_halt`, of any category, not a burner label's, and SMTP-M9-16 reads it the same way. Item 5: both copyright counts are per network, so a 2nd valid notice about another host kills the host it names; "valid" is any copyright row not lifted as wrong, "upheld" is review state `upheld`, counted per case. Item 7: while a kill stands on a host, a threat case adds nothing and a copyright notice is forwarded with no second kill; a kill that ended or was lifted stops this. Counsel reads item 5 beside §23.7's list.

Changes: §21.4; §14.8.

Questions: `abuse-core-policy-readings.md#3`, `abuse-core-policy-readings.md#5`, `abuse-core-policy-readings.md#7`.

### QD-036: Do holds reach connect-1's contract rows, given per-network keep rules cannot survive weekly drops?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §23.*

connect-1 joins `copied_rows`. At placement `AbuseHoldCopy` copies the `transfer_contract`, `contract_close` and `contract_close_report` rows naming a client of the held network that exist at placement, as compressed parts. The contract horizon reaper, `RemoveExpiredCloseEvidence` and the weekly partition drops call `AbuseHoldCopyPending` first and wait only while a hold placed before the range's end has an unfinished copy, so no keep rule is added and every drop stays whole. §21.9 and api-14 list these rows. Counsel sees this row beside §23.7's item.

Changes: §21.9; §2.8 api-14; §2.8 connect-1.

Questions: `plan-ABUSE-hold-contract-rows.md#2`.

### QD-038: How does a registrar, registry or law-enforcement notice enter §21's pipeline and page the rota?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §23.*

Both routes. (a) Registrar, registry and law-enforcement contacts name a company mailbox off the platform, for example legal@ur.io, the owner naming it, with a provider rule that fires the page; the rota files the case through the staff route. (b) `abuse.yml` gains `notice_senders`, domain to class: mail to abuse@ or postmaster@ whose DKIM verifies under a listed domain pages both rota members and opens a case, reading no body. (c) No mail or form text drives a kill: §21.8's machine host kill for a registrar's or registry's URL becomes a rota action inside the same 1 h. The public form offers no registrar or law-enforcement class.

Changes: §21.8; §21.16; D-ABUSE-3; D-ABUSE-5; §23.7.

Questions: `plan-ABUSE-notice-intake.md`.

### QD-049: What does a §21 suspension do at each gate, given only a customer can sign a `Suspend`?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §8.*

A §21 suspension is server state feeding §8.6's `hardDeny`, never a signed `Suspend` (I-4). One `abuse_action` fans out: `network_abuse_state = suspended`; a `*` kill; `SuspendZone`, so MX goes and senders retry; a mail halt from M9; every open contract closed; new contracts refused for sidecar subjects only, shares included; no `rev/`; evs and gkm untouched, so reads, writes, erasure and export continue; certificates kept unless the case orders revocation, so a lift restores service at once. §8.6's "as for §21's halts" is narrowed so it does not reach evs under a suspension.

Changes: §21.7; §21.10; §8.6.

Questions: `plan-ABUSE-suspension-effects.md`.

### QD-067: "Never the root" has no list of root and platform names to check against
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Add `protected_names: {roots: [...], platform: [...]}` to `abuse.yml`, ABUSE-M5-03's key list and §21.16, read into `AbusePolicySettings.RootNames` and `PlatformNames`. A target equal to a root is refused. A target equal to or under a platform name is refused. Once server requires sidecar, `IsReservedDnsLabel` also checks the first label under a root. Empty lists refuse every target.

Changes: §21.16; ABUSE-M5-03.

Questions: `abuse-core-protected-names.md`.

### QD-078: §21.10's record has no authentication, so a forged lift could be re-applied at a restore
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §19.*

Add `mac` to §21.10's record: HMAC-SHA-256 over the record's other fields as canonical JSON, under vault key `abuse_mailbox_mac_key`. §19.10's abuse step refuses, and prints, any record whose MAC fails or is missing, and the printed plan with its explicit apply stays. The same key covers the legal-request mailbox. Sealing alone would not do: a public key lets anyone seal a forgery.

Changes: §21.10; §19.10; D-ABUSE-7.

Questions: `plan-ABUSE-small-readings.md#16`.

### QD-088: `legal_request_mailbox` is read by §19.10 and named by no config
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §19.*

`abuse.yml` gains `legal_request_mailbox`, beside `abuse_mailbox`. It receives one record per hold placed, renewed or ended, as {event, case_id, network_id, kind, scope, place_time, expire_time}, sealed and MACed as the abuse mailbox's records are. §21.16's list and api-14 name it.

Changes: §21.16; §2.8 api-14.

Questions: `plan-ABUSE-small-readings.md#12`.

### QD-111: Trusted flaggers can trigger a machine kill, and §21 gives them no credential
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

`abuse.yml` lists `trusted_flaggers: [{id}]`. A vault file `abuse-flaggers.yml` holds, per id, the SHA-256 of a 256-bit key. `POST /abuse/report` takes `X-UR-Flagger-Key`, compared in constant time, and a match sets reporter class `trusted_flagger`. Each flagger is capped at `flagger_kills_per_day`, default 20, past which its reports take §21.8's ordinary row. Each kill's review shows the flagger id, and removing the line revokes it.

Changes: §21.8; §21.16.

Questions: `plan-ABUSE-small-readings.md#21`.

### QD-126: How abuse staff sign in and act
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §19.*

[plan-ABUSE-staff-surface] One staff route, `POST /abuse/action`, `x-internal: true`, its `kind` covering lookup, review, appeal decision, limit row, hold placement and renewal, legal request, production sign-off, restore-flag clear and mailed-action re-apply. Credential: a per-person bearer, kept hashed in vault file `abuse-staff.yml` as {reviewer_id, sha256, roles (reviewer, legal, engineering), expires}, at most 90 days old, compared in constant time. The lb refuses the route from outside the operators' addresses. Each read writes `abuse_access_log` before it answers, an appeal's reviewer must differ from the action's, and a production needs one legal and one engineering id. "Separate from ops" stays a process rule in v0, stated in §21.10, since no option stops someone holding vault or Postgres. [plan-ABUSE-small-readings#22] `bringyourctl abuse` is the staff client, with no web UI.

Changes: §21.10; §21.16; §19.4.

Questions: `plan-ABUSE-small-readings.md#22`, `plan-ABUSE-staff-surface.md`.

### QD-133: Do logs with a fixed ttl, evs-7 and ops-1, stay outside holds?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

They stay outside, and §21.9 says so plainly: "a hold does not reach evs-7's or ops-1's logs, which go at 7 d". A production still reaches them while retained. `TestEveryRetentionSweepHonorsHolds` lists both rows with that reason.

Changes: §21.9; §2.8 api-14.

Questions: `plan-ABUSE-hold-deletions.md#2`.

### QD-142: What sends role mail's auto-reply, when mx-4 keeps the envelope in memory?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §15, §14.*

Send nothing. For mail to abuse@ and postmaster@ that §14.8's header-only parse cannot attribute, the platform listener answers at end of DATA `550 5.7.1 Not read. Report abuse at https://ur.io/abuse` instead of 250 and drops the message unread. Attributed mail keeps 250 and its sealed copy, and <token>@rpt.bringyour.com mail is unchanged. The sender's own MTA returns that text to the person as a bounce, so §21.8's pointer arrives with no credential on the TCP 25 block, no backscatter from us, no third party and no stored address. §21.8's sentence becomes "the listener's refusal points senders to the form".

Changes: §21.8; D-ABUSE-5; §15.4.

Questions: `plan-ABUSE-auto-reply.md`.

### QD-194: §21.7's network standing has entry conditions but no exits or precedence
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Add to §21.7: `network_abuse_state` is derived. A state holds exactly while its Entry cell holds, re-evaluated at each action, appeal result and daily; `suspended` ends at its review. Where several hold, the first of suspended, probation, restricted, trusted, standard applies, since probation's mail rule is stricter than restricted's. A trusted network falls to standard when its Team lapses, its domain stops verifying or an action ends its clean 90 days.

Changes: §21.7.

Questions: `g0-density-text-alignments.md#9`.

### QD-195: "13 months after the case closes" hangs on a close no section defines
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

A case closes when every action is lifted or upheld by review, or, with no action, when reviewed. `abuse.yml`'s `appeal_window`, default 6 months (DSA Art. 20's floor), bounds when an appeal may be filed; a filed appeal reopens the case, which closes again at its decision. The 13 months run from the last close.

Changes: §21.10; §2.8 api-14; §21.16.

Questions: `plan-ABUSE-small-readings.md#9`.

### QD-235: Where does a name wait while `ScreenName` sends it to review?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §12.*

Review is a refusal with a case. The route answers `QuotaRefusal{limit_key: screen_review}` with the case id and stores nothing in §12's tables. A reviewer's allow is an `abuse_action` of kind `screen_allow`, naming network and name, which `ScreenFacts` reads, so the caller's retry passes. On probation a review verdict is refused with no case (§21.6). Nothing reserves the name meanwhile.

Changes: §21.6; §21.7; §12.8.

Questions: `plan-ABUSE-review-held-names.md#1`.

### QD-289: What makes a network `restricted`
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A host, label or network kill, or a network halt, within 30 days, unless review lifted it as wrong. Not counted: a burner label's halt; a §21.4 `no strike` action, meaning a protective kill for an exposed panel and a compromise halt or kill; a quota suspension (plan-QUOTA-small-readings.md#17). The question's wording missed the no-strike case.

Questions: `plan-ABUSE-small-readings.md#4`.

### QD-291: Abuse ladder and clock readings ABUSE-M5-04 landed (items 1, 2, 4, 6 and 8 to 19)
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Accept items 1, 2, 4, 6 and 8 to 19 as landed in server/model/abuse_policy.go and abuse_clock.go. ABUSE-M5-05 chooses whether a `notice_forward` row is mailed. Where plan-ABUSE-small-readings#5 says copyright counts only upheld notices, that is §21.4's third rung; the second rung counts valid notices as item 5 defines them. Items 3, 5 and 7 are held apart under abuse-core-policy-readings#3, #5 and #7.

Questions: `abuse-core-policy-readings.md`.

### QD-292: T2 for FS-48 and FS-49
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Pure tests of `model`'s policy on an injected clock stand as T2, and `.stack/server-test.sh` runs the same schedules against Postgres.

Questions: `plan-ABUSE-small-readings.md#15`.

### QD-315: Escalation counts
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

An action counts toward §21.4's "2nd in 30 d" and "3 halts in 30 d" unless review lifted it as wrong. Copyright counts only upheld notices. A `no strike` action never counts. That sentence is §21.4's third rung; the second rung counts valid notices, as abuse-core-policy-readings item 5 defines them.

Questions: `plan-ABUSE-small-readings.md#5`.

### QD-316: "Mailed, as it commits"
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The record is sent straight after commit through api's and taskworker's SES path, `mailed_time` set; `AbuseActionPass` retries rows missing it each minute. It does not ride `account_message_outbox`, whose one-minute cycle widens §21.10's "seconds" gap.

Questions: `plan-ABUSE-small-readings.md#10`.

### QD-317: What "≤24 h, in business hours" counts
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

≤24 h, 72 h and 7 d are elapsed hours; a deadline landing outside business hours moves to the next open. ≤4 business hours counts open hours only. A kill at Friday's close comes due at Monday's open, 63 h later.

Questions: `plan-ABUSE-small-readings.md#1`.

### QD-318: `network_abuse_state` rows
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A row exists only for `restricted` and `suspended`. `probation`, `standard` and `trusted` derive from `network.create_time`, tier, balances and action history, and are cached. A network 7 or more days old that fits no other row reads `standard`.

Questions: `plan-ABUSE-small-readings.md#3`.

### QD-323: What a barred case shows the network
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A barred case shows the network its standing and nothing else: no case id, category, target or appeal link. `GET /abuse/cases` omits it, `POST /abuse/appeal` answers as for an unknown case, and `GET /abuse/status` shows standing only. When a sealing order lapses the notice goes out with its case id and appeal link, and the appeal window runs from that notice. A CSAM case stays barred.

Questions: `plan-ABUSE-small-readings.md#6`.

### QD-328: Closure growth's exact test
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`model.NetworkClosureBytesToday` is above zero, `network_quota_state.storage_over` is true, and the nightly count exceeds `model.NetworkStorageLimitByteCount`. One open case per network: a case already open takes no second. No machine action.

Questions: `plan-ABUSE-small-readings.md#17`.

### QD-350: `network_verified`'s owner user
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`network.admin_user_id` until TEAM-M6-02 names an Owner. Verified means a `network_user_auth_password` row with `verified` true, or a `network_user_auth_sso` row for Apple or Google. Wallet, seed phrase and guest rows do not count.

Questions: `plan-ABUSE-small-readings.md#19`.

### QD-378: `trusted`'s tests
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Tier `team`; a verified `network_domain` row; the network's `team` grant, not its line, in window across the last 30 days with no unresolved `invoice.payment_failed`; and no action in 90 days unless lifted as wrong. The question's `paid` test is not enough: `paid` is generated from revenue columns (server/db_migrations.go:1655), and the `team_credit` line carries revenue before anything is collected.

Questions: `plan-ABUSE-small-readings.md#18`.

### QD-379: A report that joins nothing
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A report naming no URnetwork host, address or connection leaves no `abuse_case` row, and the form answers the same either way, so it is no oracle for which names exist.

Questions: `plan-ABUSE-small-readings.md#7`.

### QD-499: The feeds' shape
*Proposed fill: a gap the agents filled; work builds on it.*

`abuse.yml` lists URL feeds, each a plain text list of URLs or hosts, at most 64 MiB a fetch, keeping only names under `<root>`. Which feeds, and their licenses, stay on the external list.

Questions: `plan-ABUSE-small-readings.md#14`.

### QD-500: How a lift appears in the mailed record
*Proposed fill: a gap the agents filled; work builds on it.*

A lift has its own `action_id`, `kind: lift`, and `target` holding the lifted action's id. No new field.

Changes: §21.10.

Questions: `plan-ABUSE-small-readings.md#11`.

### QD-501: The business-hours calendar
*Proposed fill: a gap the agents filled; work builds on it.*

`abuse.yml`: `business_hours: {zone: UTC, days: [mon, tue, wed, thu, fri], open: "09:00", close: "18:00", holidays: []}`; `mode: always` is M6's 24/7. main's zone is set with the rota's staffing.

Changes: §21.16.

Questions: `plan-ABUSE-small-readings.md#2`.

### QD-502: ur.io paths
*Proposed fill: a gap the agents filled; work builds on it.*

`/abuse` (the form), `/legal/law-enforcement`, `/legal/rfc3207-deviation`, `/legal/transparency`, `/legal/canary`.

Changes: §21.11.

Questions: `plan-ABUSE-small-readings.md#23`.

### QD-554: Where the Web Risk Update API's local state lives
*Proposed fill: a gap the agents filled; work builds on it.*

Taskworker memory, refetched in full on a cold start, so no row is needed and ext-6's view is unchanged. RAW diffs only, no Rice decoding.

Questions: `plan-ABUSE-small-readings.md#13`.

<a id="s22"></a>
## §22 Testing and verification

### QD-028: May `server/test-env.sh` attest all three masters of T3's private Redis Cluster?
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Extend portable mode to take a list of Redis authorities. Each must be loopback on a port above 50000, pass `test_env_refuse_loopback_tunnel_endpoint` and the probe, and be attested by address in `WARP_TEST_ENV_ATTESTED_ADDRS`, which has room for 8. test_env_dial_guard.go stays as strict, and no other mode changes. The list stays private to the sidecar stack.

Changes: server/test-env.sh; the brief's guard limit.

Questions: `plan-TEST-t3-redis-attestation.md`.

### QD-135: §22.6 names mailgun/proxyproto, which has no license and which §4.7 refuses, and server links it in production
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §4.*

Recommended: change §22.6's PROXY bullet to name a second reader written from haproxy's proxy-protocol.txt, which is what landed, and record the one-off comparison in `.stack/scratch/tls-hello/proxydiff/`. Separately the owner decides what to do about `server/connect/transport_pp.go`, which links the unlicensed module in production: one email asking mailgun for a license, or a replacement.

Changes: §22.6; §4.7 under option 3.

Questions: `tls-hello-mailgun-proxyproto-license.md`.

### QD-200: §22.8's hdd run measures what one offered load achieved, not capacity
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §19.*

§22.8's hdd row gains a capacity step before the mix. At year two's 1:4 PUT to GET ratio, drop the page cache on every host before each step and read no object twice within a step; offer load in 10-minute steps, each 25% above the last, until achieved drive operations rise under 5% from the step before. Capacity is that plateau, by the same /sys/block stat fields 1 and 5, and it is what §19.6 publishes, with p99 at the plateau recorded. The 1 h runs at year one's and year two's mix with admission on follow unchanged.

Changes: §22.8 hdd row; §19.6 hdd row.

Questions: `g0-recheck-0-hdd-trigger.md#2`.

### QD-210: "Once C3 is tested" names no test
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §23, §6, §20.*

Add FS-126 to §22.8 (§6, T2+T3, M6-out) and to §23.6's M6 schedule: with C3 on, a forged ControlId frame over P2P is dropped; a same-network pair moves from relay to P2P and back under a live RPC and stream, its session key unchanged; Hello and HeadCheck hold across the move; and bytes on P2P debit nothing (§20.6). D-PROTO-10's "P2P is tested" means FS-126 passes.

Changes: §22.8; §23.6.

Questions: `plan-PROTO-p2p-milestone.md#2`.

### QD-239: What runs the nightly form, with no CI and no nightly job?
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

A launchd job running `sidecar/test.sh --cadence nightly` on a host the owner names, with T3's private stores on that host. During this build each gate sweep runs that form. It never takes `tests/network-intensive-suite-lock.sh`.

Changes: §22.15.

Questions: `plan-TEST-cadence-runner.md#2`.

### QD-264: How does a T3 row move time on stores that keep real time?
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

T3 keeps each row whole and translates time in one reviewed file, server/sidecart3/clock.go. The Blobs wrapper records each key's write on the schedule's clock and returns it as `LastModified`. `Advance` shortens Redis TTLs by `PEXPIRE` over the families a row names. api takes the clock through a test seam beside `DenyPostgresForTest`. A clause that depends on Postgres `now()` or a script's Redis `TIME` after an `Advance` runs on T2 only, since neither can be moved. The catalog's `store-clock` flag marks every translated clause, gate reports say so, and FS-114 and §22.9's file-cluster suite never use the wrapper. §22.8's `real` rule gains that sentence.

Changes: §22.8; D-TEST-10.

Questions: `plan-TEST-clock-seam.md#2`.

### QD-634: How does `ur evs rekey` re-checkpoint the files of a git-mode ref, which takes writes only as git pushes through the local tier?
*Decided by the owner on 2026-11-10, asked one question at a time.*

A rekey of a git-mode ref is a git-mode push with no commit, the REKEY shape of DESIGN-DETAILS 8.2: it keeps the tip, and its changes only re-checkpoint files under the current generation, each new entry's sealed mode, oid and name equal to the standing one's. Any writer's device can send it, a head-mode one included. EVS1-M2-48 builds the push rules and removes gkm_rekey.go's git-mode skip, after which §22.7's row holds for git-mode refs too.

Changes: DESIGN-DETAILS.md section 8 stands as written; EVS1-M2-48 builds it and removes the skip.

Questions: `keys-m2-26-rekey-git-mode-refs.md`.

### QD-303: Porcupine stays out of the sidecar module
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The import sits in server's tests, and `sidecartest/fault` keeps a plain recorded history. EVS1-M2-42's `dependencies.yml` row is not needed.

Questions: `plan-TEST-small-readings.md#2`.

### QD-311: A statement's id sits at field 2, behind its header
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

StatementHeader stays field 1 and ids follow at field 2. §22.6's target reads 'with equal bodies': both statements carry one header and one id, so the whole bodies match and only the type refuses them, as TestGrantRevokePresentedAsOwnerConfirmIsRefused does.

Changes: §22.6.

Questions: `protos-bridge-statement-field-one.md`.

### QD-338: `evs's gate off`
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §4.*

The engine's gate-off seam and `Net.SetEvsGate` exist only under build tag `sidecar_testhooks`, so release builds carry neither the setting nor a config key, and §4.7's hygiene row fails a release leg that links the tag. §22 picks up the name.

Changes: §22.7.

Questions: `plan-TEST-small-readings.md#9`.

### QD-340: Forging clauses inside T2+T3 rows
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Those clauses of FS-38, FS-102 and FS-124 run on T2, their honest clauses and twins on T3, and the catalog flags each.

Questions: `plan-TEST-small-readings.md#6`.

### QD-342: §22.10's ladder row omits wrap_aad, which §10.4's ladder row requires
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §10.*

The artifact's ladder row reproduces KeyDelivery's wrap_aad as well as GenWrap's, LeafWrap's and GenLink's AAD, as §10.4 says. KEYS-M2-11 already plans it; design-records aligns §22.10's row.

Changes: §22.10 ladder row, wording only.

Questions: `g0-recheck-0-readerkey-forgery.md#3`.

### QD-346: §22.7's actions row omits evs_drop_preview on a secret repo
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §16.*

§16.5 and §16.6 refuse every evs tool on kind secret, so §22.7's actions row covers all of them: add evs_drop_preview on a secret repo and on the config. The case lands with MCP-M10-01, when the tool exists.

Changes: §22.7.

Questions: `g0-recheck-2-mcp-config-read-scope.md#2`.

### QD-347: A row's purpose
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A row's purpose is its `why`, and a withdrawn row's single `withdrawn` key passes.

Questions: `plan-TEST-small-readings.md#4`.

### QD-363: Schedules live in non-test files
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A row on T2 and T3 is one exported `fault.Builder` in a non-test file. Other plans' `sidecartest/fault/fsN_test.go` names hold only the thin T2 test.

Questions: `plan-TEST-small-readings.md#1`.

### QD-372: §22.9 and FS-97 drop D-TEAM-29's "at least one"
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

D-TEAM-29's "at least one" holds: a Worker no group of the admitting device seated is never revoked in that act. Add the words at 22-TEST.md:2603 and at FS-97 (22-TEST.md:2065), which the question missed, and assert the empty case.

Changes: §22.9; FS-97.

Questions: `g0-density-text-alignments.md#6`.

### QD-374: Does D-TEST-1 mean T3's schedules gate every merge?
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

T1, T2, T4 and T3's store suites gate merges. T3's FS rows run nightly and at each Gn-out, and the explorer takes 10 seeds a merge on T2 rows and 100 a night on T3 rows.

Questions: `plan-TEST-cadence-runner.md#1`.

### QD-423: A `+T4` row
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

It is T4's when the SDK cell exists. Until M8 its T2 and T3 parts gate, and the gate report shows T4 as open.

Questions: `plan-TEST-small-readings.md#10`.

### QD-424: `ur tun ip auto` waits for its §22 evidence
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`auto` refuses behind `BridgeComponentSettings.AutoAddressEnabled`, false, until §22.9's Browsers check shows no ICE candidate in the overlay block. An explicit `<ip>` and an admin's assignment work.

Questions: `plan-BRIDGE-small-readings.md#18`.

### QD-536: `metadata_list.yml` location
*Proposed fill: a gap the agents filled; work builds on it. Also amends §2.*

At the sidecar repo root, generated byte for byte from §2.8's fenced block by `make metadata`. A row changes only through design-records.

Changes: §22.7.

Questions: `plan-TEST-small-readings.md#3`.

### QD-587: Classify is in-repo, not bart
*Settled by the agents from the design; work builds on it.*

Build an in-repo table in `device/`: prefixes flattened at build time into sorted disjoint ranges with a binary search, held to §22.5's ≤50 ns at 1,000 prefixes.

Questions: `plan-BRIDGE-small-readings.md#1`.

### QD-594: D-TEST-5's synthetic main network
*Settled by the agents from the design; work builds on it.*

No task builds it: it is Later.

Questions: `plan-TEST-small-readings.md#8`.

<a id="s23"></a>
## §23 Phasing, milestones, and rollout

### QD-132: When does the segment placement get a design and a home, and what is its lead time?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §19, §11.*

Recommended: open a tracked item now, as the next metadata cluster has. §23.7 gives it (due: before the projected crossing; start: M3's exit, when the hdd run first gives an admitted throughput) and a lead time of 26 weeks, monitor's setting hdd_trigger_lead_days = 182. A new Q-OPS item holds the placement's design, due within 8 weeks of M3's exit, §23.4's Later list and §19.18 name it, and the rota owns the page.

Changes: §23.7; §23.4 Later list; §19.18; §11.22; Q-OPS-2 residual.

Questions: `g0-recheck-0-hdd-trigger.md#3`.

### QD-247: FS-25's gate legs are due at M3-out, but the table, the route and the only gated effect arrive at M5
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §22, §16, §19, §7.*

Option 1. §16.18's M4-M9 row says `approval_use` and `POST /approval/cancel` are built dark at M3 under `sidecar_pending` and register with MG5 at M5's Gn-out (D-OPS-6 allows it, and T3 sets the tag, §19.7). §23.6's M3 row and FS-25's row say: at M3-out the gate legs (a gate's response lost after COMMIT, two api instances racing) run on real Postgres through `model.ConsumeApprovalUseInTx` with a test effect in the same transaction, and the cancel case runs through the real `POST /approval/cancel` route with §7.4's allowlist on; at M5-out the same legs run again through `POST /dns/records` (MCP-M5-01). §22.8's `real` row names this one exception until M5-out. The test effect pre-authorizes nothing: the spend check and the claim run as in production. §19.7's MG5 stands.

Changes: §23.6 M3; §22.8 FS-25; §22.8 real; §16.18 M4-M9.

Questions: `plan-MCP-fs25-gate-before-dns.md`.

### QD-274: Keep §23.8's no-duplication clause as written, or name the duplication the design keeps on purpose
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §22, §7, §9, §11, §17, §2, §3.*

Recommended: amend §23.8's clause to "no content duplicated across sections (each item in its owning section, cited elsewhere), except §2.8's published list, §3.7's flows and Requirements rows". design-records then moves the test lists out of Interfaces subsections into §22 first (11-EVS.md:3098, 17-BRIDGE.md:528, 09-SOCK.md:393, 07-TEAM.md:990) and turns accidental restatements into citations, before M2's Gn-in.

Changes: §23.8; §22; §7.17; §9.15; §11.20; §17.16.

Questions: `g0-density-rule-direction.md`.

### QD-341: Holds before counsel
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`abuse.yml`'s `holds_enabled`, default false, refuses placement until counsel confirms (§23.7). Readers of `hold/` need no gate: no object, no effect.

Questions: `plan-ABUSE-small-readings.md#20`.

### QD-401: Which milestone owns gen packs
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §19, §22.*

[g0-recheck-2-gen-pack-trigger#2] Gen packs are not in this build and have no task or FS row. Add "gen packs at §19.9's gen trigger" to §23.4's Later paragraph. If §22.8's M2 count projects the trigger inside a year, raise that at M2's exit. [plan-coverage-section-later-rows] Every section's Later row stays out of M0-M10, recorded in OUT-OF-SCOPE.md, C7 and gen packs included. A section's Later uses the word as §23.4 does, and §23.16 makes work after M9 and M10 §23.4's Later.

Changes: §23.4.

Questions: `g0-recheck-2-gen-pack-trigger.md#2`, `plan-coverage-section-later-rows.md`.

### QD-482: Enums that give names to values fields already carry as uint32
*Proposed fill: a gap the agents filled; work builds on it.*

Keep EvsPushFlag, EvsLocatorKind, EvsVersioning, EvsWindowFlag, SmtpPreambleCode and SmtpProofCode as landed. Their fields stay uint32 on the wire, they add no number, and D-PHASE-9's lint reads them.

Questions: `protos-services-unwritten-numbers.md#6`.

<a id="s0"></a>
## No section named

### QD-007: A stray link stops all landing on two repositories
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

[connect-m1-stray-self-link] Someone with authority over the main checkouts runs `rm /Users/builder/urnetwork-sidecar/connect/connect` and `rm /Users/builder/urnetwork-sidecar/userwireguard/userwireguard`, with no `-r` and no trailing slash, since `rm -r` on a trailing slash follows the link and deletes the checkout. `glog/glog` and `gvisor/gvisor` are ignored by git and can go in the same pass. Then `track-land --merge connect-m1` runs. `track-land` keeps its check, and later loops use `ln -sfn`. [connect-c14-c9-stray-symlink-blocks-landing] Duplicate of connect-m1-stray-self-link: answer that one. Once the link is gone, `track-land --merge connect-c14-c9` runs as normal.

Changes: BRIEF.md Where you work, only under options 2 and 3.

Questions: `connect-m1-stray-self-link.md`, `connect-c14-c9-stray-symlink-blocks-landing.md`.

### QD-052: Seven sdk worktrees under ~/urnetwork/temp were relinked by a mistaken `git worktree repair`
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Recommended: run the question file's restore loop, which writes fourteen one-line files, checks each before writing, and uses no `git worktree` command. Add a line to the brief: no agent runs `git worktree repair` or `prune` in a monoroot clone whose admin directory holds entries copied from `~/urnetwork`.

Changes: BRIEF.md hard limits.

Questions: `wire-consumers-sdk-worktree-links.md`.

### QD-621: What should a VPN component do when a statement that could narrow reach has waited for a compile that has not run?
*Decided by the owner on 2026-11-10, asked one question at a time.*

A VPN component never goes pending because a narrowing statement it cannot check by signature has waited for a compile. It keeps its last compiled state, applies at once every revocation it can check by signature (as before), and raises an alarm (bridge_alarm, with the waiting statement's age) once such a statement has waited NarrowingOverdueTimeout (10 min), repeating while it waits; the next compile judges every waiting statement. Forwarding never drops for this reason, at the accepted cost that a revocation the posture cannot check may not apply on a device that cannot compile. DESIGN-DETAILS.md section 4 (4.2.5, 4.3 and the Fwd.tla invariant that a revoked forwarding key is eventually refused) was built on option 1, so the design agent amends it; SDK-M8-17's plan entry carries the override until then.

Changes: DESIGN-DETAILS.md 4.2.5, 4.3 and Fwd.tla amended by the design agent; SDK-M8-17's plan entry: Details line with the override; QD-620's wording no longer says pending after 10 min.

Questions: `details-4-compile-deadline.md`.

### QD-627: Should a fold's ConfigRecords include the BASE entries, so the config head holds every entry's body and a reader recomputes the chain from the genesis through the head?
*Decided by the owner on 2026-11-10, asked one question at a time.*

A fold's ConfigRecords include the BASE entries in (after, folded_through] as ConfigRecord kind 1, the Signed ProjectionHeader as body, ignored by compile and compared by the head check like any record, so the chain A_1..A_folded_through is a function of the genesis and the head. This amends QD-456's fill ('records run in n order with no BASE') before the format freezes. DESIGN-DETAILS.md section 5 is built on this, and TEAM-M2-08, -09 and -10 have landed it.

Changes: DESIGN-DETAILS.md section 5 stands as written; TEAM-M2-08, -09 and -10 (landed) stand; QD-456's fill amended (design-records).

Questions: `details-5-base-records-in-folds.md`.

<a id="later"></a>
## Later decisions

Decisions taken after this file was generated, each naming the section it folds into. A design-records track folds the ones that name its sections, with that section's items above, and deletes them here.

### QD-652: Should closure pacing admit by seat, each seat good only in its own second, in place of a bucket that admits by arrival?
*Decided by the owner on 2026-11-10, asked one question at a time. Folds into §20 Tiers, quotas, metering, and billing.*

Closure pacing admits by seat. A seat is a 1/R cell at the tail of the network's pacing, good from its instant to the end of its calendar second; a seat is handed out only in a second with a free cell; an eraser whose seat is due takes, and nothing else is checked, so arrival order decides nothing. A refusal is not recorded under its debit id, so the same upload asks again. An eraser that misses its seat's second by more than the cell's tolerance (250 ms to 1 s at R = 4) is seated again, at once while the second has a free cell, one round later in a full network. Reading 19's 5-minute horizon and its setting go; the steady state is the landed one (k erasers each every k/R s). QUOTA-M2-14 changes QuotaClosurePacing, the fake, the {sq_} script and quotasuite's pacing cases together. This answers quota-m2-03-pacing-boundary-order with a fourth option and quota-m2-01-rate-key-grammar #3 with its other reading.

Changes: DESIGN-DETAILS.md section 13 stands as written; QUOTA-M2-14 builds it; §20.7 closure and wait rows (design-records).

Questions: `details-13-pacing-seats.md`, `quota-m2-03-pacing-boundary-order.md`.

### QD-653: Should bytes a lease spent under a reservation that has since lapsed go unbilled, and should a lease's own tokens live 15 minutes instead of 24 hours?
*Decided by the owner on 2026-11-10, asked one question at a time. Folds into §20 Tiers, quotas, metering, and billing.*

No lease byte is debited without its carve: a batch is posted only once its carves answered; bytes whose reservation was gone are dropped from the event, counted in urnetwork_quota_lease_unbilled_bytes_total and alerted; ApplyUsageBatch refuses a lease meter's event its carves do not cover. A lease's own tokens live 15 min and are extended every 5 min while the lease lives, and the host stops spending a token's bytes 30 s before it could lapse; carved tokens keep 24 h. The cost is under-billing of at most one window's bytes a host during a Redis outage as seen from that host; a dead edge's hold returns in 15 min. Lease.tla holds NoOverdraw only with this. QUOTA-M2-07 and QUOTA-M2-15 build it; landed ApplyUsageBatch and the fake's lease excess change.

Changes: DESIGN-DETAILS.md section 13 stands as written; QUOTA-M2-07 and QUOTA-M2-15 build it; §20.6 leases and loss rows, E-d (design-records).

Questions: `details-13-lease-lapse.md`.

### QD-654: Should a lease draw more than 64 MiB at a time when its traffic is fast?
*Decided by the owner on 2026-11-10, asked one question at a time. Folds into §20 Tiers, quotas, metering, and billing. Also amends §2.*

A lease's draw is 64 MiB (16 MiB on Community) or, when that is more, 4 s of the lease's own measured rate rounded up to a multiple of it, at most 16 times it (1 GiB; 256 MiB on Community), renewed with a quarter of the draw or 2 s of traffic left, whichever is more. A slow lease draws as §20.6 has it; a fast one renews about once per 4 s with 2 s to do it. A lease can hold up to 4 s of its traffic unspent, which a Redis loss can over-admit for it. §20.6's draw row and api-13's published sizes ('64 MiB to 1 GiB, 16 to 256 MiB on Community') change (design-records). QUOTA-M2-07 builds it.

Changes: DESIGN-DETAILS.md section 13 stands as written; QUOTA-M2-07 builds it; §20.6 draw row and §2.8 api-13 sizes (design-records).

Questions: `details-13-lease-draw-size.md`.

Partly folded (2026-11-10): §2.8 api-13's sizes landed with QD-657; §20.6's draw row waits for §20's fold.

### QD-655: Should a gate service refuse for a network once it knows the authorization log moved and cannot verify the new entries, where QD-055 has the last verified state keep serving?
*Decided by the owner on 2026-11-10, asked one question at a time. Folds into §8 Access control. Also amends §9.*

A sockets process answers unavailable for a network once it has had evidence for 5 s (§8.9's target for server gates) that the authorization log passed what it holds and it has not verified the new entries: the {acl_<networkId>}v event, a store answer naming a higher position, or after a resubscription a {acl_}v that differs from the one its state was loaded at. With no evidence, the last verified state serves without limit, so an api outage changes nothing (api is the log's only writer). This narrows QD-055's 'on failure the last verified projection, facts and list keep serving' to 'keep serving what nothing contradicts'. Section 13 specifies it for sockets; SOCK-M5-07 builds it; SockReg.tla checks the strict form.

Changes: DESIGN-DETAILS.md section 13 stands as written; SOCK-M5-07 builds it; QD-055 narrowed; §8.9 gates and §9.8 text (design-records).

Questions: `details-13-gate-behind.md`.

### QD-656: Should a tls/ or smtp/ Service pair live 15 minutes past its listener's last accepted registration, in place of its grant's expiry up to 24 hours?
*Decided by the owner on 2026-11-10, asked one question at a time. Folds into §9 Abstract socket listeners and the scheduler. Also amends §2.*

A tls/ or smtp/ Service pair ({svc_<listener_client_id>} field <dialer_client_id>) is written by Find with a ttl of the lesser of the grant's remaining life and 15 min; a registration call that accepts an edge entry of the client renews its pairs, at most every 5 min a process; a removal leaves a floor that refuses a write allowed at an older position. A revoked, removed or dead listener's pairs end within 15 min whatever any sweep did. ur/ pairs keep §9.6's rule (60 min, refreshed per Find). sock-3's ttl text changes (design-records). SOCK-M5-18, SOCK-M5-05 and SOCK-M5-06 build it.

Changes: DESIGN-DETAILS.md section 13 stands as written; SOCK-M5-18, -05 and -06 build it; §9.6 edge Finds and §2.8 sock-3 ttl (design-records).

Questions: `details-13-edge-pair-life.md`.

Partly folded (2026-11-10): §2.8 sock-3's ttl landed with QD-657; §9.6's edge Finds wait for §9's fold.

### QD-003: A requested grant's GrantActivate still shows its prefix and port to api, which clean rows do not fix
*Accepted by the owner on 2026-11-06, in bulk as recommended; owner decision 220. Folds into §16 The local MCP server and record primitives. Also amends §2.*

Owner decision 220's wire, which waits on the code: §16.8's CanonicalAction fence gains `bytes sealed_detail = 38` and the version it raises, and §2.8's api-7 and api-10 then say that a requested `dial` or `route` grant's GrantActivate carries its prefixes and ports only sealed. The rest is folded (2026-11-10): the decision, §17.8's placement, D-BRIDGE-6, §8.8's GrantActivate row and a comment in §16.8's fence naming the decision.

Changes: §16.8 CanonicalAction's fence; §2.8 api-7; §2.8 api-10.

Questions: `plan-BRIDGE-gate-row-prefixes.md#2`.

Waits on: record.proto's `CanonicalAction.sealed_detail` and its version (ACL-M2-07, ACL-M4-02, MCP-M3-02, RECORD-M2-01), since protocol's fence test holds §16.8's fence to record.proto, and §2.8 keeps what api sees until the wire seals it.

### QD-077: X's pin of Y's ShareKey and Y's pin of each target host's identity key have no signed home
*Accepted by the owner on 2026-11-06, in bulk as recommended. Folds into §17 IP addresses, subnet routing, and port forwarding.*

The wire, which waits on the code: §17.9's fence takes `message BridgeShareGrant { bytes share_id = 1; bytes grant_id = 2; bytes share_public_key = 3; bytes target_table_sha256 = 4; bytes table_key = 5; }` once bridge.proto declares it, and bridge.proto gains `BridgeAliasBody.host_identity_public_key = 5` with the share seal's `BridgeShareTargets` and `BridgeShareAliases` (QD-108), which no DESIGN.md fence writes. The rest is folded (2026-11-10): §17.8's BridgeAlias, §17.9's share pins, shares paragraph and target row, a comment in §17.9's fence, §8.11, §7.9's repo files and FS-38.

Changes: §17.9's fence; bridge.proto.

Questions: `plan-BRIDGE-share-pins.md`.

Waits on: bridge.proto's share messages (BRIDGE-M6-03 to -05), the fence line landing in one change with them, as protocol's fence test holds the two together.

### QD-211: The device role cannot tell a SidecarRevoke is its own sign-out
*Accepted by the owner on 2026-11-06, in bulk as recommended. Folds into §17 IP addresses, subnet routing, and port forwarding.*

The fence, which waits: §17.8's `Pending` fence takes `bytes sidecar_id = 3; bytes identity_public_key = 4;`, which bridge.proto already declares and protocol/design_unfenced_test.go's `testFenceAdditions` holds (plan-SDK-pending-sidecar-id). The fence line and the dropped additions must land in one commit, which a design-records track, editing no code, cannot make alone (question `dr-s17-s18-fence-additions.md`). The rest is folded (2026-11-10): §17.8's legacy -> pending and any -> legacy rows with a comment in the fence, and §18.6's transitions.

Changes: §17.8 Pending's fence; protocol/design_unfenced_test.go's testFenceAdditions.

Questions: `plan-SDK-pending-sidecar-id.md`.

### QD-658: How does a git-mode push with no change at all go in parts, when its sealed metadata passes 1 MiB?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

A statement in parts may state an empty change list: change_count 0, changes_root the root of zero parts with changes (SHA-256 of the empty string, RFC 9162's empty tree), no changed_prefixes, and every part changeless. A git-mode push whose net change is empty but whose carried commits and history blobs pass one part (a tag over a long unheld history, or an UPDATE whose tip tree is unchanged) then goes in parts. §11.6's statement shape and the seal's root for zero changeful parts change before M2's freeze; every parser and the seal check take it. EVS1-M2-48 builds it; until then the builder refuses such a push before anything is sent.

Changes: §11.6 statement and parts rows (design-records); EVS1-M2-48: statement shape, ParseEvsStatement, the seal's root, the builder.

Questions: `evs1-m2-48-changeless-push-in-parts.md`.

### QD-659: Which member device may form the group of a repo an agent creates, when no config writer reads that repo or holds its admin scope?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §10 Group keys for evs: MLS and the GKM service.*

QD-638's former stays as built for M2: a config writer forms the group of a repo an agent creates only when it is a key holder of the repo (R3) and holds admin on it at gkm, which §8.5's implicit document always gives every member device. An agent's repo needs a member device that reads and administers it; under a narrower ACL document with none, the repo stays keying (fails closed, nothing leaks). Revisit when Team policies can narrow member devices' evs rights (M6), with the first acting config writer filing RepoGrant{reader} and RepoAdmin{add} for itself as the candidate.

Changes: KF1 §10.7 and §8.8 RepoCreate notes (design-records); M6 revisit noted on TEAM/ACL policy tasks.

Questions: `keys-m2-32-agent-repo-former-rights.md`.

### QD-660: Should a push attempt read evs's newest authorization state again when it reruns steps 4 and 5, instead of judging 5d against the gate view it bound at arrival?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

A push attempt reads GateViews.View(network) again at each run of step 4, the first and every rerun (after step 7's 5 s window passes or after a 412), and judges 5d's gate predicate against that newest view; bind's read at arrival stays for 5b's identity check only. One map read per rerun, no I/O. This is §11.8's timing row ('against the newest authorization state evs holds'). The fix is in evsservice/push.go and push_step4.go (EVS1-M2-12's code, the data lane); then TestFs3StepSevenPastFiveSeconds runs beside TestFs3 under FS-3's rules.

Changes: data-lane follow-up: evsservice/push.go and push_step4.go re-read the gate view per step 4 run; TestFs3StepSevenPastFiveSeconds added beside TestFs3.

Questions: `evs1-m2-40-gate-view-rerun.md`.

### QD-661: Should a seal record's part item accept the root's empty token path, which a push in parts that creates a top-level name names as its first part's?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

ParseEvsSealRecordBody accepts a part item of exactly 52 bytes (place 20 B + changes_root 32 B, no token bytes) as the root's empty first token path, which EvsSealRecordBody already writes for a push in parts whose first change is the root's delta (EVS1-M2-46). EVS-FORMAT.md says so, with a round-trip test. Every other parser of token paths in records (evs_batch.go and its siblings, EVS1-M2-04/12's code) is checked for the same gap. FS-9 can then create its directory at the top level.

Changes: data-lane follow-up: evs_batch.go's ParseEvsSealRecordBody and other record token-path parsers; EVS-FORMAT.md; round-trip test; FS-9 un-nests its directory.

Questions: `evs1-m2-40-seal-root-part.md`.

### QD-662: How should evs's read reply carry a directory at its 448 KiB bound whose rows are still in unfolded deltas spread over a push's parts, when one path frame cannot hold them?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

evs's read reply carries a path's unfolded directory deltas across frames, a delta per frame with its proofs beside it, so any directory within its 448 KiB bound lists in any fold state, and the frame bound (1 MiB + 64 KiB) stays. A frame that cannot be encoded is logged and the stream ends with an error frame, never silently. EVS-FORMAT.md states the frame contents. The read route's owner (EVS1-M2-14's code, evsservice/read_frame.go, the data lane) builds it; FS-9's unfolded listing then runs.

Changes: data-lane follow-up: evsservice/read_frame.go splits deltas across frames, logs and ends a stream that cannot encode; EVS-FORMAT.md read frames; FS-9 unfolded half.

Questions: `evs1-m2-40-unfolded-listing-frame.md`.

### QD-663: A LIST on the local stack's MinIO leaves out a key whose overwrite is in flight, with every drive online, so section 2.2.2's whole LIST does not hold for keys evs rewrites in place: should the fork make such a LIST whole, or should evs stop deciding on one?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

The in-house MinIO build makes a LIST whole for a key whose overwrite is in flight too: a key some asked drive holds but whose xl.meta read failed other than not-found is read again under the key's lock, or the LIST answers 503 rather than leave it out (an EVSB-M2-22 rule, with the probes in .stack/scratch/evs1-m2-40/minio-probe/ as its T3 test). DESIGN-DETAILS 2.2.2's 'a LIST that is whole' then holds as written, and evs's listers need nothing. Until the fork's rule lands, the fold's markBelow (evsservice/marker.go), the one site found that decides on what a LIST leaves out, lists twice and takes the union. FI-1 keeps reading known heads and slots by key.

Changes: EVSB follow-up in the minio fork: whole LIST for keys mid-overwrite (cmd/metacache-walk.go, metacache-set.go, metacache-entries.go) with the probe as test; data-lane interim: markBelow lists twice and unions; DESIGN-DETAILS 2.2.2 stands.

Questions: `evs1-m2-41-list-drops-overwritten-key.md`.

### QD-664: Should evs's newest rule find a window version's record through pidx/ once evacuation has moved its batch, as a read's statements already do?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

RecordPushSource falls back to RecordLocator.ReadRecord (pidx/) on ErrEvsRecordEvacuated and caches the record, as read_proof.go's readRecordAt already does (§11.13: a batch's records are found through pidx/ once it is gone). Every caller of NewRecordPushSource (the newest rule in evsservice/newest.go, fold, purge, collect, push step 4 and the log route) gains the fallback. No new head write. The data lane's follow-up (EVS1-M2-09's code); then TestFs7EvacuatedWindowAfterRestart runs beside TestFs7.

Changes: data-lane follow-up: RecordPushSource's pidx/ fallback with cache (evsservice/newest.go and record source); TestFs7EvacuatedWindowAfterRestart added.

Questions: `evs1-m2-41-newest-evacuated-window.md`.

### QD-665: Should evs's read routes refuse a deleted repo 409 REPO_DELETED and a shredding or shredded one 409 SHREDDING, as §11.12's refused row closes every route but restore and DELETE with now?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

The read, refs and log routes in evsservice/read.go and POST/GET/DELETE /evs/v1/subscriptions in subscribe.go set RefuseDeleted: a deleted repo answers 409 REPO_DELETED, a shredding or shredded one 409 SHREDDING, as §11.12's refused row closes every route but restore and DELETE with now. One repo/ read per request, from the 5 s repo cache the upload route uses. The data lane's follow-up (EVS1-M2-14's and EVS1-M2-15's code); then TestFs6ReadsRefusedWhileDeleted runs the clause.

Changes: data-lane follow-up: RefuseDeleted on evsservice/read.go's three routes and subscribe.go's routes, with tests; TestFs6ReadsRefusedWhileDeleted added.

Questions: `evs1-m2-41-reads-of-deleted-repo.md`.

### QD-666: Why does a reader fail to open a file a PATH_EPOCH's tail carried, created in the source epoch by a push of a newer generation, until evs's copy has run?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

A reader opens each sealed name or record of an unfolded version with the key of the generation its statement names (the push's own generation), not the epoch's or the tail move's p_new, per DESIGN-DETAILS 9.2.4 and 9.2.5, so a generation-ahead creation carried by a PATH_EPOCH tail reads through its source before evs's copy runs. Every committed version stays readable across any cut-over (9.1, P2). The data lane's follow-up in EVS1-M2-28's read path (evs_epoch_read.go, evs_proof.go), or EVS1-M2-26's sealing rule if 9.2's text puts the key choice there; then TestFs4BatchedEpochReadBeforeCopy runs the clause.

Changes: data-lane follow-up: the read path opens sealed values with the statement's generation (evs_epoch_read.go, evs_proof.go); TestFs4BatchedEpochReadBeforeCopy added.

Questions: `evs1-m2-41-tail-creation-read.md`.

### QD-667: Should the config head carry a bridge ledger, the frozen body-level state of every folded bridge statement, checked by every full reader as rows are?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §17 IP addresses, subnet routing, and port forwarding.*

The config head carries a bridge ledger: files of rows by kind (bridge/ledger/addresses with tombstones, rules/<xx> shards by id with their bodies and dispositions, egress, aliases) and a manifest of their hashes. A writer writes them at each fold from the verdicts it holds; every full reader standing under the previous base computes the same files and forks on a difference; a device that starts at the base, and a VPN component, take them. The files are ciphertext at evs, so no §2.8 row; about 600 KB at 5,000 devices. This carries section 5's rule (a verdict judged once by the verifiers present, taken from the base after) to bodies the server cannot read, and bounds every compile. DESIGN-DETAILS.md section 12 is built on it; BRIDGE-M4-23 builds it with seams in TEAM's writer and head check.

Changes: DESIGN-DETAILS.md section 12 stands as written; BRIDGE-M4-23 and BRIDGE-M4-16 build it; §17.8 and §7.9 text (design-records).

Questions: `details-12-ledger-in-head.md`.

### QD-668: What judges a bridge filing's approval after a base that did not fold it: the new base's rows, or a verdict carried from the entry's own position?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §17 IP addresses, subnet routing, and port forwarding.*

A bridge filing in a base's tail is judged by every reader that holds its body's key on the new base's rows with the tail re-applied (section 5), as BRIDGE-M2-01 already judges a signer; the writer freezes the verdict into the head's bridge ledger when it folds the entry, and writers fold through their tip whenever a bridge statement is unfolded. The one case that differs from a verdict at the entry's own position (a head landing within seconds of an approved filing whose policy disqualifies that approval) turns the verdict at every reader alike and fails closed; the requester files again under a new decision. No format beyond the ledger (QD-667). DESIGN-DETAILS.md section 12 is built on it.

Changes: DESIGN-DETAILS.md section 12 stands as written; BRIDGE-M4-23 builds it.

Questions: `details-12-unfolded-verdicts.md`.

### QD-669: After a restart, should a daemon host serve bridge flows before its judge has replayed the denials it had applied?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §17 IP addresses, subnet routing, and port forwarding.*

At a daemon's start, and at each new client generation, the bridge provider is built only after every entry above the restored state that the ConfigClient holds has been replayed to the bridge (and a compile at the tip has run if one can), from local stores alone, given section 12's rule that an entry is in the ConfigClient's store before any entry callback runs. If the client's store is behind the posture's pin, the provider waits for the follow to reach it, with bridge_alarm after 30 s. A host whose config store lagged its posture at a crash serves no bridge flow until it reaches api again. Nothing a restart does lowers enforcement. An app's VPN component has no resident judge and is unchanged (section 4; QD-621). BRIDGE-M4-17 builds it; until the core lane reverses ConfigClient.publish's order, the gate's wait for the follow covers that gap.

Changes: DESIGN-DETAILS.md section 12 stands as written; BRIDGE-M4-17 builds the start gate; core-lane follow-up: ConfigClient.publish stores entries before running entry callbacks.

Questions: `details-12-start-gate.md`.

### QD-670: How do the sharing network's hosts trust the accepting network's alias table: by a hash their approving admin pinned, or by the seal alone?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §17 IP addresses, subnet routing, and port forwarding.*

X's approving admin pins the accepting network's alias table as QD-077 pins the target table: BridgeShareGrant gains the accepting network's id and each table's hash and version (fields 6 to 9), written in the act that files the share's GrantActivate. A host compiles a share only from tables that hash to the pins. The alias table holds each alias's host bits (the low 16 bits) and length, and X's host matches a destination's low 16 bits, so a block change in Y changes nothing X pinned. If Y ever re-aliases a share, X's admin activates again. The fields join QD-077's message before bridge.proto declares it. DESIGN-DETAILS.md section 12 is built on it; BRIDGE-M6-03 builds it.

Changes: DESIGN-DETAILS.md section 12 stands as written; BRIDGE-M6-03 builds it (bridge.proto BridgeShareGrant 6 to 9); §17.9 share pins (design-records).

Questions: `details-12-alias-table-pin.md`.

### QD-671: When does a host store a share's raised config generation: before it admits the contract that carried it, or after?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §17 IP addresses, subnet routing, and port forwarding.*

When a share-link contract's ShareCert names a generation above the host's ratchet for that share, the host commits the raise to §17.8's persisted posture store and then admits the contract. One store commit per share per rotation of Y, a few milliseconds, in that one contract's VerifyPrincipal sequence before the dial, never a packet's, a flow's or a later contract's; R-BRIDGE-9's no-I/O-per-packet rule is untouched. A removed sidecar stays refused after a host restart, as FS-38 asks. DESIGN-DETAILS.md section 12 is built on it; BRIDGE-M6-04 builds it.

Changes: DESIGN-DETAILS.md section 12 stands as written; BRIDGE-M6-04 builds it; §17.9 admit row (design-records).

Questions: `details-12-ratchet-commit.md`.

### QD-672: Should evs serve a removed path's earlier versions by number, so History of a removed path walks them rather than repeating its removal?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

evsservice serves path.version < newest.RemovalVersion by number from the entry's folded versions, as it does for a standing path (read.go's pathReply), so History of a removed path walks its earlier versions and §11.12's closure can list each retained version's slot keys. EvsRepo.History stops a walk that does not descend and raises an alarm, since a server repeating itself is this bug or a tamper. EVS1's code (read.go, evs_history.go) with tests in read_test.go and evs_history's; a data-lane follow-up. Until it lands MAIL-M8-02 keeps its fail-closed rules: a vault delete commits its ERASE before its removal, and a delete of a vault path removed without an ERASE refuses with ErrMailVaultNotShreddable.

Changes: data-lane follow-up: evsservice/read.go serves a removed path's older versions by number; evs_history.go stops a non-descending walk with an alarm; MAIL-M8-02's interim rules stand.

Questions: `mail-m8-02-history-of-a-removed-path.md`.

### QD-673: What keeps a mailbox's EvsShare subjects and audit reader out of its vault entries, which only the owner's consented devices may read?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §15 The local email server, inbound mail, and burner email.*

Vault entries are narrowed by rule. §16.6's refused-from-MCP list and MCP-M3-12's McpGuard add every evs tool, search tool and ur://evs resource on a mailbox's vault/ family, and evs_list omits it, so an agent holding an EvsShare of the mailbox reaches vault entries by no path. §15.8 and §2.18 state the residual: a mailbox's EvsShare subjects and a Team's audit reader hold the keys that open vault entries, and clients (MailVault refusing every device but the owner's consented ones) enforce the narrower readership. A second seal to an owner-only vault key stays the option if the readership must later hold against a holder of the mailbox's keys.

Changes: §16.6 refused list and McpGuard row for a mailbox's vault/ family (edge lane, MCP-M3-12's code); §15.8 and §2.18 residual sentences (design-records).

Questions: `mail-m8-02-vault-readers.md`.

### QD-674: Should every repo move from Go 1.27.3 to 1.27.4 for GO-2026-6859, which now fails make check's govulncheck rule, and may sidecar tracks land meanwhile?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §4 Repositories, code placement, branches, and build.*

Every repo moves from Go 1.27.3 to go1.27.4 for GO-2026-6859 (an HTTP/1 server crash in net/http) in one coordinated ops-lane change: the go directive in every go.mod of connect, sidecar, sdk, server and sn, any toolchain line, the build images' Go base, any check/ rule that names the version, and R-REPO-6's and §4.9's pin. D-TEST-15's one-toolchain rule holds (x/text chooses tables by go1.27, which a patch release does not change). The go1.27.4 toolchain comes through the module proxy, checked against the checksum database (QD-025), as lowgo already uses it; check/ accepts no advisory. The host's /usr/local/go is the owner's to update; the run does not touch it, and lowgo keeps go1.27.4 first on PATH until then.

Changes: ops-lane track go-1-27-4: go.mod go directives in connect, sidecar, sdk, server and sn; build images; check/ rules naming the version; R-REPO-6 and §4.9 pin to 1.27.4.

Questions: `team-m2-21-govulncheck-go-1-27-4.md`.

### QD-675: When a forwarding Delegation's row leaves the rows before gkm's reconciler deleted its reader key object, what deletes gkm/dkey/<delegation_id> within its published ttl?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §10 Group keys for evs: MLS and the GKM service.*

gkm's reconciler keeps a tracked end of a forwarding Delegation after its row leaves the rows (QD-648) and deletes gkm/dkey/<delegation_id> on schedule, DelegationKeyRetention (24 h) after the end. After a restart, a sweep of the network's gkm/dkey/ prefix, now and then, deletes at once any object whose id no forwarding row in the state's rows names: its row is gone, so its retention has passed by at least 4,096 positions and nothing a rotator seals still needs it. §2.8's published ttl then holds at any entry rate and across restarts; no row or format changes. A KEYS-lane change in sidecar/gkmservice/reconciler.go (core lane).

Changes: core-lane follow-up (KEYS): gkmservice/reconciler.go keeps tracked ends past their rows and sweeps gkm/dkey/ for unnamed ids; §2.8's gkm ttl text stands.

Questions: `team-m2-21-dropped-forwarding-key-objects.md`.

### QD-676: What should a VPN component's posture do once its overlay is full and no compile has run to clear it?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §18 SDK, apps, and extension integration.*

A VPN component's posture overlay moves to the component's sealed store in the review phase, streamed and indexed with only an index and a cache in RAM, as QD-641 directs for bulk state (DESIGN-DETAILS 4.2.4's storage-backed compile is the same move for rows), so its only bound is storage's and the host's per-flow check reads the index. Until it lands, the interim as built stands: past PostureSettings.OverlayMaxCount (4,096) a denial the posture verified and cannot hold sets PostureDecision.OverlayFullThroughN (manifest field 23), the decision is pending until a state at or past it, the posture keeps following the chain, and it alarms malformed once a call. A posture that can no longer hold a denial it can check denies rather than silently stops applying them; QD-621's accepted cost covers only revocations the posture cannot check.

Changes: review-phase task: storage-backed overlay in device/ (QD-641); interim in device/posture_apply.go stands.

Questions: `sdk-m8-17-overlay-bound-without-compiles.md`.

### QD-677: How should the soak count orphan objects by orphan GC's own definition, when evsservice has no count that deletes nothing?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §22 Testing and verification.*

EVSB adds a dry form to evsservice/gc_orphans.go: OrphanGc.CountRepo(ctx, repo *OrphanGcRepo) (*OrphanGcResult, error) runs steps 0 to 4 and step 5's selection, issues no DELETE, and reports CandidateCount and the count of those no pidx/ entry introduces, sharing orphan GC's one definition. The soak (server/local/sidecar-soak) implements its orphanCounter through it per repo over the nightly pass's listings and compares what GC would judge orphan, past the horizon, at the baseline and at the end. Until it lands the orphan signal reads open, as built. A data-lane follow-up of about forty lines.

Changes: data-lane follow-up: OrphanGc.CountRepo in evsservice/gc_orphans.go; server/local/sidecar-soak's orphanCounter wired to it.

Questions: `test-m2-03-soak-orphan-count.md`.

### QD-678: Should the lb leave X-Frame-Options off the key origin, sidecar.ur.io, when today it adds `SAMEORIGIN` to every service host's responses?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §18 SDK, apps, and extension integration.*

warp's services.yml gains a list of exact hosts the lb sends no X-Frame-Options for, shaped like no_access_log and checked the same way (an exact host the lb serves); warp/services/sidecar-blocks/mmm.yml adds sidecar.ur.io to it. warpctl's addSecurityHeaders skips the header for a listed host, and a warp config test asserts the key origin's server block has no X-Frame-Options while every other host keeps SAMEORIGIN. The key origin's framing then rests on mmm's CSP frame-ancestors https://ur.io alone, as SDK-M4-06's trap says, and ur.io keeps its own protection. An ops-lane change to warp's addServiceBlocks; it lands before the owner applies mmm.yml.

Changes: ops-lane follow-up: warp services.yml no-frame-options host list, warpctl/config.go addSecurityHeaders, config test; mmm.yml fragment line for sidecar.ur.io.

Questions: `ops-m4-01-lb-frame-options.md`.

### QD-679: Are these readings of §8.8's compile right, where CompileAcl had to fix a form the answers name without bytes?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §8 Access control.*

The seven readings of §8.8's compile stand as written in acl-m2-04-compile-readings.md and as the code on sidecar does them: (1) the config head's tags, groups, rules, labels and resolve files are protocol/config.proto's ConfigAtomTable, ConfigRuleTable, ConfigLabelTable and ConfigResolution, none server-visible, so no §2.8 row; (2) a rule's canonical form is RFC 8785 JCS of one JSON object per rule with lists sorted as strings and id and note left out, a request writing its effective evidence, expires_default and max_expiry so a change of the document's defaults is a change of meaning (FS-14); (3) the implicit document's rule i counts its grants then its requests, and §8.5's tag:mail kind-default rules take ids from SHA-256("urnetwork-sidecar-v1/acl-kind-rule" || 0x00 || u32be(i)), i 0 the read and 1 the deposit; (4) network:* compiles to a derived atom of kind 4 over the one byte '*', naming no subject until §8.11's shares (ACL-M6-03); (5) compile drops an activated grant whose expiry is at or before the head's newest record time, and a member the log's rows no longer hold expands to nothing; (6) a grant allowing route adds its via subjects to its targets (QD-004); (7) AclEngine honors a rule until AclEngineSettings.ClockSkew (60 s) past its expiry by the local clock. design-records names readings 1 to 4 in §8.8 and §7.9's file list. No code change.

Changes: §8.8 and §7.9's file list name readings 1 to 4 (design-records); no code change.

Questions: `acl-m2-04-compile-readings.md`.

### QD-680: Which task builds api's end of `/internal/gate/` (the projection and rows routes and their per-caller bearer check), and what body does the projection route answer?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §8 Access control.*

A new ACL task builds api's end of QD-055's internal gate surface: GET /internal/gate/projection/<network_id>?after=<n> answering the Client route's body (TEAM-M2-13's NetworkConfigProjectionResult: {genesis, entries, rows, tip: {n, chain}, more}, each message verbatim in base64, paged, from the retention point when after is before it) as a thin wrap of model.ConfigLogSequencer.Read, and GET /internal/gate/rows/<network_id>/<rows_sha256> answering the ProjectionRows bytes verbatim (application/octet-stream), which the client holds to their hash; both behind a per-caller bearer verified by SHA-256 in constant time as QD-027 words it, with one caller-class vault file per gate service (connect first; the owner creates the files), the routes in server/api/api.go and route_authz.go, and the lb's refusal of the /internal/gate/ prefix from outside (W8's allow list). The listen-facts and over-limit routes join when SOCK and QUOTA need them. One encoding then serves devices and gates.

Changes: new task ACL-M4-02: api's /internal/gate/ projection and rows handlers, bearer check, routes, lb prefix refusal; owner: one vault file per gate caller class, connect first.

Questions: `acl-m4-01-internal-gate-routes.md`.

### QD-681: How does a reader verify a directory delta in a walked statement whose change list is under changes_root, when the read reply has no place for its inclusion proof?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

EvsReadPathReply gains repeated EvsDeltaProof delta_proofs = 19, one per entry of deltas in order, with message EvsDeltaProof { repeated EvsMerkleProof proof = 1; }, empty for an inline statement; EvsAbsenceProof gains EvsMerkleProof present = 5: for a prefix among a walked statement's changes, that change's inclusion proof in place of below and above, which the reader accepts only for a strict prefix whose change writes an entry (a delta) and refuses for the path itself or a removal. §11.9's reply row reads 'that neither the path nor a removal of a prefix holding it is among its changes, with the inclusion proof of a prefix's delta that is'. evs's read.go and read_proof.go build both from the push record they already read, and evs_proof.go checks them. Two proto fields before M2's freeze; no new server-visible data. The data lane's follow-up; the code track declares the fields and lists them in protocol/design_unfenced_test.go's testFenceAdditions, and design-records then writes them into DESIGN.md's evs.proto fence and drops those lines (QD-684).

Changes: data-lane follow-up: evs.proto EvsReadPathReply.delta_proofs = 19, EvsDeltaProof, EvsAbsenceProof.present = 5, listed in testFenceAdditions until design-records folds the fence; evsservice read.go, read_proof.go; evs_proof.go; §11.9 reply row.

Questions: `evs1-m2-28-rooted-delta-proofs.md`.

### QD-682: Where does an ERASE's and a CLOSURE's sealed note go, and what are its bytes?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

An ERASE's and a CLOSURE's note go in a new EvsSealedMetadata.erasure_note (bytes), sealed with the push's metadata: erasure id 16 B | complete u8 (1 when this push ends the erasure) | the caller's note bytes (RECORD's SealedNote, MAIL's documents); a CLOSURE's note holds its erasure id and no caller bytes. The ERASE then creates nothing on the erasure ref (evs takes a creates-only push of no change, which the landed checks allow), and reconcile resumes an erasure from evs's state as §11.12 says. EVS-FORMAT.md states the layout; evs-6's words in §2.8 and metadata_list.yml name the field if they list sealed metadata's contents. The data lane's follow-up in EVS1-M2-30's code (record_seam.go's RecordStreamErase and the ERASE and CLOSURE builders), with the new field listed in protocol/design_unfenced_test.go's testFenceAdditions until design-records writes it into DESIGN.md's evs.proto fence (QD-684).

Changes: data-lane follow-up: EvsSealedMetadata.erasure_note, ERASE and CLOSURE builders, reconcile reads it; EVS-FORMAT.md layout; testFenceAdditions until design-records folds the fence; §11.12 push and rekey rows.

Questions: `evs1-m2-30-erasure-note-format.md`.

### QD-683: May a design-records track add the code-side line a new design id needs, a new §2.8 row's `rows:` line in testdata/metadata/fields.yml or a new §4 id's line in check/repo_matrix_test.go, since each guard needs both in one commit?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §2 Trust model and threat model.*

A design-records track that adds a new §2.8 row or a new §4 id adds the code-side line its guard needs in the same commit: the row's planned line in testdata/metadata/fields.yml's rows: section (ext-11 for Cloudflare terminating https://ur.io, QD-012, and ext-12 for the abuse and legal-request mailboxes' provider, QD-030, each planned at the milestone that first serves its value), and a new id's repoMatrix entry in check/repo_matrix_test.go (Q-REPO-6 for QD-023's apt upgrade item, mapped to a path or rule that holds the install path as Q-REPO-4 and Q-REPO-5 are). One line of test data or test code per id, outside the design files otherwise; the row and its planned line are one fact. The design-records brief allows exactly these lines.

Changes: design-records brief: may add a new id's fields.yml rows: line and repoMatrix entry in the same commit; follow-up design-records track: ext-11, ext-12 and Q-REPO-6.

Questions: `dr-s2-s3-new-metadata-rows.md`.

### QD-684: May a design-records track drop a field's line from protocol's fence additions in the commit that writes that field into its DESIGN.md fence, since the fence test fails until both change together?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §4 Repositories, code placement, branches, and build.*

A design-records track that writes a field into its DESIGN.md proto fence drops that field's line from protocol/design_unfenced_test.go's testFenceAdditions or testFenceValueAdditions in the same commit, touching only those list entries. The list carries a field the code declares until design-records folds it, so dropping its line is the fold's other half; the fence rule stands (never move a fence ahead of the code). First use: §17.8's Pending fence takes sidecar_id = 3 and identity_public_key = 4 (QD-211); Pending.forward_delegation_id = 5 and BridgeIdentity's fields 6 and 7 (DESIGN-DETAILS 4.2.2) follow when section 4 is folded. Answered with dr-s2-s3-new-metadata-rows (QD-683); the design-records brief allows exactly these edits.

Changes: design-records brief: may drop a folded field's line from protocol/design_unfenced_test.go's additions lists in the same commit; follow-up design-records track: §17.8 Pending fence for QD-211.

Questions: `dr-s17-s18-fence-additions.md`.

### QD-685: Should a search-index diff rest only on a full entry in its own writer's files, which that writer keeps, so that no merge or other device's push can take a base from under it?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

A search-index diff rests on a full entry of its document in another file of its own writer in its own bucket, a slot that is not the head or a large entry, and on nothing else. The writer keeps that file while a diff of its unabsorbed slots rests on it: it does not reuse such a slot or remove such a large entry. Every push that writes a writer's file replaces that writer's head at the version read, so a writer's pushes commit one at a time. A merge reads no head and removes no writer's file. No cross-device dependency is left to race (IndexMerge.tla passes with every writer push free to land across any merge, and each rule has a twin that fails without it). Costs accepted: a writer's first entry of a document in a bucket is full until the head holding it seals; a writer keeps up to 8 slots (128 KiB) a bucket past their absorption; an absorbed large entry waits for its writer's next push there or the bucket's roll-up. This supersedes the questions search-m10-07-keep-base-full-copy and search-m10-07-merge-stale-diff. DESIGN-DETAILS.md section 1 is built on it; SEARCH-M10-45, SEARCH-M10-10 and SEARCH-M10-11 carry it.

Changes: DESIGN-DETAILS.md section 1 stands as written; SEARCH-M10-45, SEARCH-M10-10, SEARCH-M10-11; §11.14 slot, entry, dependency, seal and merges rows (design-records).

Questions: `details-1-own-bases.md`.

### QD-686: Should a roll-up move a version or tombstone that a newer bucket holds only older entries of into that bucket's shards, instead of rewriting the newer bucket's files in place?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

A roll-up writes a carried version or tombstone into the shards of the newest bucket holding an entry of its document, in the roll-up's push, which replaces or creates that bucket's manifest. Nothing is removed from the newer bucket: reads mask its older entries by version, its merges drop them, and its own roll-up carries the promoted entry on; a promoted tombstone still takes all's row. No in-place rewrite and no writer's file touched; a merge of the target conflicts on its manifest CAS. I-EVS-11's last clause and FI-20 gain 'or a newer bucket's shards', and §11.14's 'every all row is older than each bucket entry of its key' becomes 'no all row is newer than the newest bucket entry of its key'. This supersedes the question search-m10-07-rollup-merge-race. DESIGN-DETAILS.md section 1 is built on it; SEARCH-M10-11 carries it.

Changes: DESIGN-DETAILS.md section 1 stands as written; SEARCH-M10-11; §11.14 roll-up rows, I-EVS-11 and FI-20 wording (design-records).

Questions: `details-1-promotion.md`.

### QD-687: What keeps an index entry that trails its content from landing below a tombstone a roll-up has already dropped: the content pin and a push lifetime on the client, or a counter evs enforces?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

An index push's builder takes its signed time, reads the index head, then reads each content ref's head from evs, and drops an entry whose document that pin holds at a higher version or removed. It sends the push only within 5 min of its signed time (25 min for a push in parts) and never sends a stored push again after 429 TIME_AHEAD. A merge names no expired bucket and a roll-up only an expired one, both judged at the push's signed time. Hosts with the text check each live entry against its path and backfill a missing tombstone. No server change; the argument rests on evs's 10 min time check and on clients not sending stored pushes. The accepted residual: a device whose clock ran about a week fast when it built, that stalls that long and then sends the stored bytes; a host with the text then repairs the index and names the signer. If the review phase wants the residual closed, evs's head counter moved at every roll-up (refusing an index push built before it) is the named fallback. This supersedes the question search-m10-07-late-journal-tombstone. DESIGN-DETAILS.md section 1 is built on it; SEARCH-M10-14 and SEARCH-M10-12 carry it.

Changes: DESIGN-DETAILS.md section 1 stands as written; SEARCH-M10-14, SEARCH-M10-12; §11.14 companion, coverage and roll-up rows (design-records); review phase: evs roll-up counter named as the fallback.

Questions: `details-1-late-entries.md`.

### QD-688: Should a merge keep rewriting every shard that holds an older version of a document it carries, or leave superseded rows in place until their shard is half dead?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

A merge keeps §11.14's rule: it appends new rows to the youngest shard and drops a document's older version from the shard holding it, so a bucket's shards hold one version per document (I-EVS-11); an eraser finds a document in one shard of each partition, and reads mask across partitions only. The cost for an edited repository (DESIGN-DETAILS 1.4's figures) is accepted for now. In the review phase, before M10's exit freezes the bytes, the lazy alternative (a merge leaves superseded rows masked by version, rewrites a shard under half current, and a roll-up carries winners only) is measured on FS-76's corpus, since it reaches into the erasure's bounds (owner decision 146), which section 1 does not own.

Changes: DESIGN-DETAILS.md section 1 stands as written; review phase: measure lazy superseded rows on FS-76's corpus before M10's exit.

Questions: `details-1-superseded-rows.md`.

### QD-689: Are these fourteen readings of §11.14 right, where section 1 of DESIGN-DETAILS.md had to choose and no D- item is changed?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

The fourteen readings of §11.14 in details-1-small-readings.md stand as DESIGN-DETAILS.md section 1 writes them: (1) a bucket's expiry is judged at the push's signed time, never the device's clock; (2) a slot other than the head, or a large entry, at or below its writer's absorbed seq holds nothing for search, merges and roll-ups, only a diff's base; (3) a manifest may exist with no shard, and absorbed holds a row only for a watermark above 0; (4) IndexFileHeader.coverage sorts by ref_id then horizon false before true, at most one row of each kind a ref (protocol/INDEX-FORMAT.md's 'strictly ascending by ref_id' is corrected); (5) an entry's time is its content push's signed time and its bucket follows the index push's; (6) a merge's tie order at one version is a tombstone, the shards' own entry, then the full entry from the lowest writer id and the lowest seq; (7) the youngest shard fills by section 1.2.4's fixed binary search; (8) a merge with nothing to add still commits its manifest; (9) a push past 256 KiB of entries also writes its writer's head; (10) the lock renews at half its term; (11) a companion push that only raises coverage is sent; (12) a writer replacing a multi-chunk text file without its text writes no index entry, and the push is backfilled; (13) a roll-up's runner writes horizon rows at indexed_through into its own head in the newest bucket for each content ref the removed slots named; (14) a journaled unit at or below its ref's horizon at the companion push's base is dropped. design-records folds them with section 1's text.

Changes: DESIGN-DETAILS.md section 1 stands as written; protocol/INDEX-FORMAT.md coverage order (with SEARCH-M10-45); §11.14 rows (design-records).

Questions: `details-1-small-readings.md`.

### QD-690: Should extractor 1 define its own base64, quoted-printable, character-reference, header and whitespace rules, so that no standard-library parser's behavior is part of the index format?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

Extractor 1 defines its own base64, quoted-printable, HTML character-reference, header and whitespace rules: every such reading is a rule of the index format, written in DESIGN-DETAILS.md 11.2 and protocol/INDEX-FORMAT.md, with HTML's reference table in the repository (testdata/index/conformance/entities.json) and 372 conformance vectors holding both implementations (the index's extractor and SearchOracle's) to it. No standard-library parser's behavior is part of the format, so a Go release can no longer change an index, and no text is lost at a long quoted-printable line, a control byte or a missing pad. It replaces three sentences of QD-474: references are the format's rule and not html.UnescapeString; a charset label is read as bytes; labels of the replacement encoding pass as bytes. About 400 lines in each implementation and some 32 KB of table on the legs that index. DESIGN-DETAILS.md section 11 is built on it; SEARCH-M10-42 and SEARCH-M10-43 carry it.

Changes: DESIGN-DETAILS.md section 11 stands as written; SEARCH-M10-42, SEARCH-M10-43; INDEX-FORMAT.md Extractor 1; QD-474's three sentences replaced.

Questions: `details-11-own-decoders.md`.

### QD-691: Should extractor 1 cut a header value at 16,384 B and read a delimiter line or soft line break past 1,024 B as text, so that a phone can extract any message in one pass and fixed memory?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

Extractor 1 cuts a logical header line, and the joined values of one header name, at HeaderMax 16,384 B, and reads a multipart delimiter line or a quoted-printable soft line break whose trailing blank run passes LineWindow 1,024 B as text. Extraction then runs in one pass in at most 150 KiB beyond the normalizer, whatever the message, so a phone extracts any message in fixed memory (§11.15's working set; QD-641). Both limits are format bytes, far above RFC 5322's 998 B line and RFC 2046's 70 B boundary; a header value's tail past 16 KiB is not indexed, where fields 1 to 3 keep only 1,024 normalized bytes anyway. DESIGN-DETAILS.md section 11 is built on it; SEARCH-M10-42, SEARCH-M10-43 and SEARCH-M10-44 carry it.

Changes: DESIGN-DETAILS.md section 11 stands as written; SEARCH-M10-42, SEARCH-M10-43, SEARCH-M10-44; INDEX-FORMAT.md Extractor 1 limits.

Questions: `details-11-extraction-bounds.md`.

### QD-692: Should a remote-search body that is not the one deterministic encoding of its message, or that holds a field its receiver does not know, be refused?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

A remote-search receiver accepts a body only if it holds no field the receiver does not know, at any depth, and marshaling the parsed message deterministically gives the same bytes; then it checks that pad is zeros. A request that fails is INVALID and a reply that fails is no reply. The version is judged first, so a later version's request is UNSUPPORTED_VERSION, not INVALID. A message then has one body, so the size rule, the pad rule, the size tests and the fuzz target all speak of one encoding. A later requester must raise search_version to send a new field (SearchRequest's reserved 13 and 14 included), and falls back to version 1's fields for an indexer that answers a lower range. One more marshal and a comparison per body. DESIGN-DETAILS.md section 11 is built on it; SEARCH-M10-31 carries it.

Changes: DESIGN-DETAILS.md section 11 stands as written; SEARCH-M10-31; §11.14 status row (design-records).

Questions: `details-11-body-encoding.md`.

### QD-693: Are these thirteen readings of extractor 1 and of the search body caps right, where §11.14 and protocol/INDEX-FORMAT.md are silent and the two landed implementations differ or lean on a library?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

The thirteen readings of extractor 1 and the search body caps in details-11-small-readings.md stand as DESIGN-DETAILS.md section 11 writes them, each pinned by a vector in sidecar/testdata/index/conformance/: (1) a file's UTF-8 byte-order mark is dropped (S3); (2) names compare by ASCII case and only ASCII whitespace is trimmed (11.2.1); (3) an unterminated multipart's last part keeps its last line break (B4); (4) of two RFC 2231 pieces of one name, kind and section the first counts, and sections that join to nothing fall through to the extended piece and then the plain one (P3, P5); (5) a section number is 1 to 9 digits (P3); (6) base64 decodes a last partial group and inside an encoded word skips nothing (T2, W3); (7) quoted-printable passes control bytes, has no line limit and keeps a line's trailing blanks, and a soft line break may hold blanks before its line end (T3); (8) a numeric character reference needs one digit, &#x; is text, a number past U+10FFFF is U+FFFD, and all 2,231 of HTML's names decode (E1, E2); (9) SearchHit.correction is at most 256 B and SearchCoverage.chain at most 32 B (Z4); (10) extractor 1 keeps its number; (11) a part directly inside a multipart/digest with no Content-Type is message/rfc822 and not entered (M1); (12) the block-tag list stays QD-474's 44 names (X4); (13) format=flowed is not read (11.5).

Changes: DESIGN-DETAILS.md section 11 stands as written; INDEX-FORMAT.md Extractor 1 (with SEARCH-M10-42 and SEARCH-M10-43); §11.14 extract, sniff and sizes rows (design-records).

Questions: `details-11-small-readings.md`.

### QD-694: Should MAIL-M7-11's message parser call extractor 1's HTML and charset functions once SEARCH-M10-42 lands, so that an i/ snippet keeps saying what search indexes?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §15 The local email server, inbound mail, and burner email.*

Once SEARCH-M10-42 has landed, MAIL-M7-11's message parser calls extractor 1's functions: mailHtmlText calls indexStripHtml and mailDecodeCharset calls indexDecodeCharset, and the mail lane's copies (its tag scanner, html.UnescapeString and htmlindex.Get) go, so an i/ snippet reads HTML and charsets as search indexes them. Encoded words, transfer encodings and the walk stay the mail lane's own readings: they feed MAIL-FORMAT.md's fields, which no other device rebuilds. An edge-lane change of a few lines in sidecar/mail_parse.go and mail_parse_text.go, after SEARCH-M10-42.

Changes: edge-lane follow-up after SEARCH-M10-42: mail_parse.go and mail_parse_text.go call indexStripHtml and indexDecodeCharset.

Questions: `details-11-mail-snippet-reading.md`.

### QD-695: Should section 6 accept the window in which a wrapped writer, or a leaf whose seal races a poisoned commit, seals to the generation the commit carried until the refusing member's REMOVE rotation reaches it?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §10 Group keys for evs: MLS and the GKM service.*

Section 6's window stands as accepted: after a compromised leaf's commit whose tree holds a party dropped at the commit's own header, a wrapped writer (which reads no commit), and a leaf whose seal races the injection, may seal to the generation the commit carried until the refusing member's REMOVE rotation reaches it. The commit needs a compromised leaf, which already holds that generation's key and could hand the dropped party the same content or the key itself, so the window adds no reach the attacker lacks; the refuser's rotation at once ends it. No rule, format or model change; DESIGN-DETAILS.md 6.3's text stands.

Changes: DESIGN-DETAILS.md section 6 stands as written; §10.9 notes the accepted window (design-records).

Questions: `details-6-poison-window.md`.

### QD-696: Should a VPN component's narrowing_overdue alarm back off while a narrowing entry keeps waiting for a compile that never runs, instead of repeating every 10 minutes forever?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §18 SDK, apps, and extension integration.*

A VPN component raises bridge_alarm narrowing_overdue when a narrowing entry has waited NarrowingOverdueTimeout (10 min) for a compile, then again at doubling intervals (20 min, 40 min, and so on) up to once a day while the condition lasts, and at once again whenever a further narrowing entry becomes overdue; the condition (the oldest overdue position and its age) stays visible in the posture's status throughout, and the first compile that runs clears it. DESIGN-DETAILS 4.2.5 and 4.3's StalenessBound read 'raised for it, and again at doubling intervals to once a day and for each newly overdue entry', and Fwd.tla's alarm clause follows (the design agent's section 4 amendment); SDK-M8-17's code (device/posture.go and its timer) follows in the core lane. QD-621's accepted cost is unchanged.

Changes: design agent: section 4 amendment, 4.2.5 and 4.3 StalenessBound wording, Fwd.tla alarm clause; core-lane follow-up: device/ posture alarm timer backs off (SDK-M8-17's code).

Questions: `details-4-overdue-alarm-repeat.md`.

### QD-697: How does server's source-graph lock move to go1.27.4, when only the owner hand-edits lock.yml and runs a real re-pin?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §4 Repositories, code placement, branches, and build.*

Once the go1.27.4 bumps land in every repo, the orchestrator sets server/local/source-graph/lock.yml's go line to 1.27.4 and runs build/all/sidecar-branches.zsh repin, which moves each sibling's pin and build's gitlinks to its current sidecar tip and commits both in server and build (no push; the next checkpoint push carries them). The owner authorized this one hand edit and re-pin on 2026-11-11; otherwise lock.yml edits and real re-pins stay the owner's (REPO-M0-03).

Changes: server/local/source-graph/lock.yml go line 1.27.4; build/all/sidecar-branches.zsh repin after the bump lands.

Questions: `go-1-27-4-source-lock.md`.

### QD-698: Do the two measurement harnesses that pin go1.27.3 on purpose move to go1.27.4 with the repos?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §4 Repositories, code placement, branches, and build.*

Server's competition evaluator (server/connect/sim-latency's image digest, GOVERSION guards and toolchain-policy test, server/competitionagent and server/cli/competitionsubeval) and the tests repo's perf runner (tests/runner/perf, whose h1 diagnostic requires a go1.27.3 producer and preflight manifest) stay on go1.27.3, so their frozen baselines stay comparable; they move when the owner re-qualifies them, at the latest before sidecar merges to main. On these branches the evaluator image cannot build server's module, which now requires 1.27.4, and a perf run of these branches would fail the h1 preflight. Neither harness module depends on a bumped module, so both still build. Records of past runs stay as written.

Changes: no change to the two harnesses; before sidecar merges to main: re-qualify both on go1.27.4.

Questions: `go-1-27-4-harnesses.md`.

### QD-699: Does a head reader decide whether a version is listed from the DROP's signed body alone, or does listed_sha256 become a Merkle root with proofs?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

A head reader decides whether a version was dropped from the DROP's signed body alone, checked against the name and version it asked for (DESIGN-DETAILS 10.2.3's H0 to H7); listed_sha256 stays one flat SHA-256 over the listed entry hashes and no reader is sent a list or a proof. What a DROP drops is fixed by its body and the ref's history (10.3's L1); a drop whose list disagrees with its body never executes, so for every drop that deletes anything, listed and covered by the body are the same set. A head reader fetches at most 257.1 KiB a drop, once, typically 1.4 KiB. The one case where readers differ, a DROP whose signer's own list disagrees with its own body, is invalid to a replaying reader, taken by its body at a head reader, and refused by the job either way. No format change and no proof code.

Changes: none: DESIGN-DETAILS section 10, EVS2-M10-10 and EVS2-M10-22 are built on this option.

Questions: `details-10-list-commitment.md`.

### QD-700: Should a DROP's body be held to 256 KiB and its lists to 1,048,576 values in all, a larger drop going in several pushes?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

A DROP's body (EvsDropHistory) is at most 262,144 B and the counts of a DROP's paths at most 1,048,576 in all; evs refuses past either (400 INVALID, 409 DROP_LIST). The client cuts a larger drop into several DROP pushes at lineage boundaries, each previewed, confirmed once as one command; one lineage that alone passes a bound (1,725 epochs at depth 8, 449 at depth 32) is refused locally. A --recursive drop of 1,024 files fits one push while a lineage averages 256 B, takes 3 pushes at depth 32 and about 200 in a repository 300 epochs old, each counted by evs_drops_per_day. If that push count ever bites in an old repository, counting the pushes of one command as one drop is D-QUOTA-12's owner's to decide then.

Changes: none: DESIGN-DETAILS section 10, EVS2-M10-36, EVS2-M10-09 and EVS2-M10-20 are built on this option.

Questions: `details-10-drop-bounds.md`.

### QD-701: Should the drop job wait until evacuation's horizon has passed the time evs saw each drop committed by 12 min, not 2, since a reuse source's head may be 10 min stale?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

This amends QD-626's 2 min. The drop job takes its mark only once evacuation's horizon has passed each covered drop's seen_ms by 12 min (10 min of head cache, 5 s of step 7's window, the clocks, and slack). The drop table's entry gains seen_ms, the appender's clock read after the answer that showed it the commit, so the job holds a time no earlier than the commit. The head cache stamps an entry with its committed head's own written_ms, never later than the clock, so a process paused between a commit and its put cannot stretch a stale head past 10 min. This closes the hole TLC found (DropJobWritten-CachedHead): a push validated after the commit on a cached head, creating its ref, whose head write stalls, landing after the job's deletes. A now drop's deletes start 25 h 12 min to 26 h 12 min after it, 10 min later than QD-626 had them; a 7-day drop is unaffected. The push path (step 4's cached reuse read, FS-91 (c)) stays as it is.

Changes: QD-626's 2 min becomes 12 min, counted from seen_ms; the drop table's entry gains seen_ms (EVSB-M10-03); the landed head cache stamps an entry with its head's written_ms (EVS2-M10-36).

Questions: `details-10-cite-bound.md`.

### QD-702: Do protocol and format limits also live in settings objects, or only tunables, now that the owner wants configuration objects for all settings and no global constants?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §6 The sidecar subprotocol.*

Every value that sets a limit, size, count, time, interval, threshold, retry or budget is a field of its owning component's settings object, set only by that object's Default...Settings() constructor and read from the instance where it is used; no package-level const or var holds one, and no such literal is written into logic. This includes protocol and format limits (the 4,080 B chunk, a DROP's 256 KiB body and 1,048,576 list values, the 1 MiB part, maximum call timeouts): their defaults are the protocol's values, and changing one is a protocol change, so a deployment does not change it on one side alone, but code and tests read it from settings. Only identifiers stay named constants: enum values, proto field numbers, error, type and statement codes, version numbers, magic strings, and cryptographic constants (such as the empty tree's SHA-256). connect/CODESTYLE.md's 'Exceptions are facts, not tunables' bullet and D-PROTO-16 narrow to identifiers, and every section that calls a limit a constant reads as a settings field. Scope: all code the sidecar run wrote, in every repo, moves now; upstream code that predates the run moves when a change touches it (CODESTYLE's 'Migrate when you touch it'); vendored third_party code stays as its upstream wrote it. Tests may still use literals to configure settings.

Changes: connect/CODESTYLE.md: the exceptions bullet narrows to identifiers; D-PROTO-16 and every section naming a limit as a constant (design-records); BRIEF.md: every track follows the rule from 2026-11-11; a settings sweep of the code the run wrote, per area, scheduled in the lanes.

Questions: `owner-settings-objects.md`.

### QD-703: Should a drop delete a candidate only once evacuation's horizon has passed its LastModified + 24 h + 2 min, in place of "over 25 h old"?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

A drop's candidate is young, and kept for a later round, until the round's evacuation horizon has passed its LastModified + 24 h + 2 min, the rule owner decision 203 chose for orphans, in place of §11.13's 'under 25 h old at V'; I-EVS-15 and FI-27 (4) take those words. It closes the hole TLC found (DropJobWritten-YoungAdopter): a push that creates its ref, adopts the receipt just before 24 h and stalls its head write was seen by no scan. Nothing changes for a drop with the 7-day window, whose candidates are over a week old; a now drop of a version uploaded an hour before it keeps that version's segments until about 49 h after their upload, where §11.13 said 25 h. With QD-702, the 24 h and 2 min are settings fields whose defaults are those values.

Changes: none: DESIGN-DETAILS section 10, EVSB-M10-06 and EVSB-M10-03's dry run are built on this option.

Questions: `details-10-young-horizon.md`.

### QD-704: Should a drop job keep its listed versions' entry hashes for the repo's life, so evs finds a listed version by its entry hash?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

The drop job's resolve, which enumerates the exact listed set anyway, writes it sorted by entry hash to dropscan/<repo>/<job id>/list-<n>, with a small index and a bloom filter, kept for the repo's life; evs finds a listed version by its entry hash, which it holds wherever it serves a version, and answers dropped for it, never serving an inline record of its chain. This holds after the drop table forgets an executed drop at 30 d (QD-179), for a path dropped at a removed boundary, for a marked path later removed, and for a record read by push id in an older epoch. It costs 36.5 B a listed version on the segment cluster (36.5 MiB at 2^20), outside any network's stored bytes. §11.8's dropscan/ row and §2.8's evs-28 ttl change for this one file kind; marker collection and the path-epoch copy are untouched, and the drop mark stays the fence's, gaining only a removed boundary's mark on its marker entry (DESIGN-DETAILS 10.2.7).

Changes: none: DESIGN-DETAILS section 10, EVSB-M10-04 (writes the files) and EVS2-M10-10 (reads them) are built on this option; §2.8's evs-28 ttl and §11.8's dropscan/ row (design-records).

Questions: `details-10-listed-index.md`.

### QD-705: Should a head-mode device sign a drop only for a history it walked itself, within 4 MiB, a longer one going to a device that mirrors the repo?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

A head-mode device builds a DROP's list only by walking the path's versions through §11.9's history reads, each statement verified, within a 4 MiB fetch budget (HeadDropFetchByteCount, a settings field under QD-702; about 4,000 to 8,000 versions across the drop's lineages). A longer history answers ErrEvsDropTooLarge (EVS_DROP_TOO_LARGE), naming ur history drop on a device that mirrors the repo. It takes only map_parts from the dry run, on which nothing but the job's own read cost rests, so the signed list stays the signer's own enumeration that FI-27 (1) checks against evs's. A phone cannot drop a path with more versions than that; DropHistory stays on the SDK's surface (§18.5).

Changes: none: DESIGN-DETAILS section 10, EVS2-M10-20 and EVS2-M10-21 are built on this option.

Questions: `details-10-head-signer.md`.

### QD-706: When does the sweep that moves the drafted code's constant tunables into settings objects (QD-702) run?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §23 Phasing, milestones, and rollout.*

The sweep that moves the drafted code's constant tunables and limits into settings objects (QD-702) runs in the review phase, area by area as the review reads each area, not during the draft phase. Until then new code follows QD-702 and every track moves the constants in the files it touches (BRIEF.md); the remaining constants stay in drafted code. The 2026-11-11 scan (.stack/scratch/settings-sweep-scan-2026-11-11.json) lists about 801 constants in 351 sidecar files that no remaining task names; the review phase also sweeps the run's code in server, connect and sdk.

Changes: review phase: one settings sweep per area, from the 2026-11-11 scan.

Questions: `owner-settings-sweep-timing.md`.

### QD-707: When is a second own search indexer asked beside the first, since §11.14 has own indexers "hedged in parallel" and gives no delay?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

A remote search asks the first two own search indexers at once, for the repos each may answer, and both own pairs are kept warm from each foreground (the foreground Hello and its keepalive hold two own pairs). No contract opens at a search on either own pair, and the tail is the faster of the two; the first page 0 to serve a repo wins it and the other reply is dropped. Every search costs two exchanges and two indexers' CPU, and the foreground costs a second own pair's window floor, 512 KiB of transfer balance an hour more. There is no hedge delay: Search.RemoteHedgeDelay does not exist. Other members' indexers are still asked one at a time, after their notice, as section 7 has them.

Changes: DESIGN-DETAILS section 7 is amended from option 1 to this (7.2.3, 7.2.4, 7.2.8's costs, 7.6's tests, 7.7's task notes, 7.8's DESIGN.md text), including how two own warm pairs and another member's warm pair combine; PROTO-M10-06's warm pairs and SEARCH-M10-33's ask change scope; both are held until the amendment lands; §11.14's order row and §18.4's remote row and targets (design-records).

Questions: `details-7-hedge.md`.

### QD-708: Should a verified or confirmed claim outrank a possible one at any version when a phone merges remote search results, since "the higher version wins" contradicts "the phone's own confirmed hits always stay"?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

When a phone merges remote search pages with its own hits, each (repo, ref, doc_key) row is its strongest claim by class first: a verified or confirmed claim before a possible one before a near one; then the higher version; then verified before confirmed; then an indexer's claim before the phone's. The phone's own confirmed hits stay matches, as §11.14's merge row's second sentence says, and no indexer can demote what another source claimed as a match by claiming a higher version in a weaker state (RemoteMergeTwin-VersionFirst). A claim verified at an older version can be shown above a newer possible claim of the same document; opening it reads the newest version and judges that, with no alarm.

Changes: none: DESIGN-DETAILS section 7 and SEARCH-M10-34 are built on this option; §11.14's merge row (design-records).

Questions: `details-7-match-first.md`.

### QD-709: Should a phone fold its own possible matches only where it can show the indexer saw their push (its own pin no higher than the indexer's, or a time more than 40 min below the pinned push's), and raise an omission alarm only at equal pins?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

A phone folds a local possible or near hit that no page returned only when the index rides the content ref and the phone's own pin of it is at or below the leg's pinned version, or the hit's time is more than 40 min below ref_time_ms (the only test for a companion index, whose entries trail their content); the 40 min is evs's 10 min clock bound plus 30 min for a push in parts (§11.8's 5b), and with QD-702 it is a settings field (SkewGuard). It raises search_alarm {omission} only when the index rides the content ref, the leg's pinned (version, chain) equals the phone's own pin, the confirming field is not cut at its cap, and the repo's uncovered is 0. When the phone is ahead of the indexer, its possible matches from the 40 min before the indexer's pin stay possible instead of folding; an omission between unequal pins raises nothing, and the phone's confirmed row stays on screen either way. Carrying each index entry's ref version (option 3) stays a review-phase option if the unfolded window matters on FS-76's corpus.

Changes: none: DESIGN-DETAILS section 7 and SEARCH-M10-34 are built on this option; §11.14's merge and ranking rows (design-records); review phase: weigh option 3 on FS-76's corpus.

Questions: `details-7-fold-guard.md`.

### QD-710: Should a device stop searching a cached all that is older than a roll-up once it no longer holds that roll-up's bucket as the roll-up read it, where §11.14's retained row keeps searching it?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

A device searches its cached all only while it is usable: its pin is the snapshot's, or every roll-up between the two pins is bridged by the rolled bucket, held as the roll-up read it (which the device knows from the statements it replayed). When a bridge is lost or cannot be vouched for (an ERASE, two windows passed, a roll-up slept through, or a bucket copy older than the roll-up's input), the device searches its buckets only, reports its coverage from the oldest bucket, and fetches all's changed files (a/m and the youngest shards, usually a few MiB) at its next window or at search more, which fetches before it answers. No deleted document is found again (IndexSyncTwin-StaleAllSearched, IndexSyncTwin-RetainStale); a phone that loses a bridge loses its instant coverage past the buckets until that fetch.

Changes: none: DESIGN-DETAILS section 7 and SEARCH-M10-19 are built on this option; §11.14's retained and roll-up rows (design-records).

Questions: `details-7-stale-all.md`.

### QD-711: Are these eleven readings of §11.14, §18.4 and §7.9 right, where section 7 of DESIGN-DETAILS.md had to choose and no D- item is changed?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §11 Encrypted versioned storage.*

The eleven readings in DESIGN-DETAILS section 7 stand: (1) a personal network, for eligibility, is a config state with one member (7.2.2's E5); (2) candidates run newest first over every partition, all's shards read only when the order reaches all's newest row; (3) a read lost mid-cursor ends the cursor, CURSOR_EXPIRED on the next page and a refusal in the reopened search's coverage; (4) a reopened search resumes by narrowing until_ms to the last checked_through_ms, with no new field; (5) an indexer remembers an ended search_id for CursorTimeout and answers every page of it CURSOR_EXPIRED; (6) a losing reply is dropped, not merged, which now covers QD-707's two own indexers asked at once; (7) the first own choice is the own indexer that answered last within 10 min, then the rendezvous order; (8) another member's indexer is sticky over the search's whole scope for 24 h; (9) a refused repo is not asked of that indexer for 10 min and a failed indexer is skipped 2 min, both in RAM only; (10) is replaced by QD-707: both own pairs are kept warm, and section 7's amendment settles how another member's warm pair fits; (11) a/m, the erasure set and the settings file are in the latest set every searching device keeps. With QD-702 every time and count here is a settings field.

Changes: none beyond QD-707's amendment of section 7.

Questions: `details-7-small-readings.md`.

### QD-712: May one perfectly hiding commitment to a mail session's keys be public, so that the TLS key schedule is proven once a connection and not in every proof part?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §14 The SMTP edge.*

This reverses QD-144's keeping of D-SMTP-22 as written. Part 1 proves the TLS key schedule (Z1) once per connection and publishes one perfectly hiding Pedersen commitment C, over the curve embedded in BN254's scalar field, to both directions' keys and IVs, plus one such commitment per header or DATA body record after the first to the scan's state between records; every later part opens C (3,261 constraints against Z1's 708,498). C is a uniformly random group element whatever the keys are, so the edge learns nothing from it even with unbounded computation or the setup's trapdoor: D-SMTP-22's purpose, that the edge holds nothing that helps open application data (D-SMTP-21, §2.8 smtp-2), holds in full, and its sentence changes to allow these commitments. Its secrecy rests on a 251-bit blind drawn uniformly from the same source as the TLS keys; soundness (abuse control only) on discrete logs on the embedded curve, about 2^125. It makes one 2^20 domain for every circuit, eleven shapes in two families in place of 22 over four sizes, about 1.3 GiB a proof measured, and any recipient count on one connection with no recipient class (DESIGN-DETAILS 3.2.2, 3.3).

Changes: D-SMTP-22's sentence and §14.5's relation (design-records); SMTP-M9-36 to -39 build the commitment, the unit shapes, the gate and the prover; released from their hold.

Questions: `details-3-key-commitment.md`.

### QD-713: What do D-SMTP-16's m5.large rows become, given that no relation over these circuits proves the gate's send there in 60 s?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §14 The SMTP edge.*

D-SMTP-16's rows are stated in proof units; the M1's numbers stay (met by projection: 2 to 3 s for the first part, 15 to 21 s for the send, about 4 min for DATA); the m5.large's become what SMTP-M9-32's bench measures, about 150 s for the gate's send and 35 min for 100 KiB of DATA by projection until then, as QD-144's rule for a confirmed miss says. No relation over these circuits meets 60 s there: the AES keystream for a 4 KiB header block alone is 2.99M constraints, 73 s at 41,000 a second. A 2 vCPU host takes about two minutes to send to an AES MX and still sends; the client offers ChaCha20 first, five units where the MX follows. With QD-702 the targets are settings with these defaults.

Changes: D-SMTP-16's Speed text (DESIGN-DETAILS 3.8; design-records); SMTP-M9-32's bench sets the m5.large numbers.

Questions: `details-3-speed-bar.md`.

### QD-714: Are many recipients at one domain sent in envelope groups on one connection, each group's replies proven with the next, rather than by a recipient class or by splitting the send?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §14 The SMTP edge.*

Many recipients at one domain go as envelope groups on one connection: the sidecar sends a group of commands (MAIL and 12 RCPT, then 13 a group, under AES; 18 and then 19 under ChaCha20), waits for the group's replies, and proves them with the next group. A send costs one quota unit and is one transaction at the MX, and each further 12 to 19 recipients add one proof part; `smtp_recipients_per_message` caps the connection, as §20.4's comment reads. The sender does not split a domain's recipients over connections, and there is no recipient class of larger shapes: with the key schedule proven once (QD-712) a part is small, which removes the premise of `smtp-m9-22-recipient-classes`. With QD-702 the group sizes are settings with these defaults.

Changes: SMTP-M9-39 builds the envelope groups; SMTP-M9-08 builds no split; no recipient-class shapes (DESIGN-DETAILS 3.1 B, 3.2.4, 3.2.6, 3.9; design-records).

Questions: `details-3-recipient-groups.md`, `smtp-m9-22-recipient-classes.md`.

### QD-715: When is the proofs' setup ceremony run again over unchanged circuits?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §14 The SMTP edge.*

The proofs' Groth16 setup ceremony runs again, and a new key set replaces the old, only when a circuit changes, when the shape catalog changes, or when the ceremony host is suspected exposed; a key set over unchanged circuits is not rotated on a schedule or with each release. A key set may still gain shapes without replacing the rest (DESIGN-DETAILS.md 3.2.7). A leaked ceremony secret lets its holder forge proof parts under that set, which defeats abuse control for forged sends (§14.8's DKIM joins still attribute them) and exposes no mail; prover hosts check every key against the setup's transcript, so a sidecar's privacy does not rest on the ceremony. Who runs the production ceremony, and on which host, stays an external action outside this run.

Changes: DESIGN-DETAILS.md 3.2.7, 3.5 and 3.9 stand as written (design-records).

Questions: `details-3-key-rotation.md`.

### QD-716: Can §2.8's smtp-2 row be amended and a smtp-7 row added for what section 3's proofs and key fetch show a server?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §2 Trust model and threat model.*

§2.8's metadata list, in its next version, amends smtp-2 and adds smtp-7 as DESIGN-DETAILS.md 3.8 writes them. smtp-2 (smtpedge, connection memory only) lists the id of the key set the sidecar proves under; a proof per part (the key part, one per envelope group, one per header record and, in DATA mode, one per body record), each with its reply count and, once, the header block's record count; and the key commitment and scan-state commitments the sidecar publishes, uniformly random group elements that depend on no key and no plaintext. smtp-7 is new: the key set path on ur.io, where per fetch the origin sees the client's address and time, the key set's id and the file names fetched, which mark the address as a mail prover host, on which key set and with which TLS families prepared; the request carries no account, token, cookie or sidecar id. Its ttl reads "as ur.io's other static downloads (§4.10)", which the ops owner confirms against how ur.io serves and logs its static files (EX7). The key set fetch stays off until smtp-7 has landed (I-18). Key sets are fetched, not bundled in the `ur` package, as QD-123 decided.

Changes: §2.8 smtp-2 amended and smtp-7 added (DESIGN-DETAILS 3.8; design-records); SMTP-M9-35's proto fields and SMTP-M9-40's fetch may reach a release once smtp-7 has landed; the ops owner confirms smtp-7's ttl line (EX7).

Questions: `details-3-metadata-rows.md`.

### QD-717: How does evs match a token's ur_sidecar_id to §5's binding, when the authorization log carries no client ids and evs has no Postgres?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §11 Encrypted versioned storage.*

evs takes a token's (ur_sidecar_id, ur_client_id) pair as §5's binding, as the exchange resolved it when it minted the token (exchangeClientSidecarId reads model.GetSidecarIdentityByClient), and checks in its own state only that ur_sidecar_id is an admitted, unrevoked sidecar of the token's network. A rebind's old client can read for at most a token's life (15 minutes); its writes are already voided by the rev/ object every write reads. No lookup route, cache or log field is added: a looked-up binding would be api's assertion just as the token is. §11.8's Authorization row reads "an admitted, unrevoked sidecar of the token's network, as the exchange bound it".

Changes: §11.8's Authorization row (design-records); EvsBindingSource goes and the real EvsAuthState's MatchBinding checks admission and revocation in the token's network (evsservice/auth_state_acl.go, engine.go).

Questions: `acl-m2-11-evs-binding-source.md`.

### QD-718: Who builds gkm's authorization state over the gate cache, GkmAuthState for the gkm block and GkmReconcilerState for taskworker's reconciler, which no plan's Provides names?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §10 Group keys for evs: MLS and the GKM service.*

A KEYS task after ACL-M2-14 builds both real seams in gkmservice over AclGateCache's exported API: GkmAuthState (a token's standing and honored scope through ACL-M2-14's HonorScope for the gkm audience, with the gkm-only answers KEYS defines: readers, writers, pins, Delegations, late holders and HoldersDropped over sidecar.GkmRemoveDue) and GkmReconcilerState (each network's moves, the networks the host holds, a network's newest state as a GkmAuthView, and a sidecar's network). ACL adds to AclGateCache, as a small separate change in its own files, the list of networks it holds, an index from a sidecar to the network that admits it, and a callback when a network's new state is installed, so a reconciler woken by a hint reads the new snapshot. Every gate check stays in ACL's one cache (C-09); until both land the gkm block and taskworker's reconciler stay failed closed as built.

Changes: a KEYS task builds GkmAuthState and GkmReconcilerState in gkmservice; AclGateCache gains its network list, a sidecar-to-network index and an installed-state callback.

Questions: `keys-m2-17-gkm-auth-state-owner.md`.

### QD-719: Where does the config repo's own AclRepo row come from, since no RepoCreate files it and every gate reads it?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §8 Access control.*

When a state's rows hold no AclRepo for the network's config repo, ACL's state build (NewAclState or ConfigState.Acl, acl_state.go) adds AclRepo{repo_id: Genesis.config_repo_id, kind: config} with no admins, so the kind's defaults answer it alike in every reader, gate and api, all of which hold the Genesis. No rows bytes change: base 1's compile stays empty and CompileAcl copies only the statements' repos, and a RepoCreate of kind config stays refused. The exchange's repo:<config_repo_id>:r and :rw, a forward_only client's config r (owner decision 197), evs's and gkm's HonorScope of config scopes, and evs's PUT of the config repo at bootstrap then answer from that row.

Changes: ACL's state build adds the config repo's row from the Genesis (acl_state.go); the hand-built config rows in acl_evs_test.go's fixture and sidecartest/gkmschedule/world.go can go.

Questions: `team-m2-15-config-repo-acl-row.md`.

### QD-720: Where may api keep a team IdP sign-in's flow state (state, nonce, PKCE verifier, the user that began it) between its start and GET /auth/sso/callback, and under which §2.8 row?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §7 Networks, teams, members, enrollment, and SSO.*

api keeps a team IdP sign-in's flow state (state, nonce, PKCE code_verifier, IdP, network, redirect, and the signed-in user that began it, for D-TEAM-23's JIT link) under a Redis key {sso_<state>} as JSON, set with a 10-minute ttl and taken with GETDEL, so a replayed state finds nothing. §2.8's api-3 gains "IdP sign-in flows in progress (state, nonce, PKCE verifier, IdP, network, the signed-in user that began one; 10 min, taken once)". The state is soft: a lost Redis only restarts sign-ins in flight, as §19.7 allows. No table and no cookie. The ttl is a settings field with 10 minutes as its default (QD-702).

Changes: §2.8's api-3 row gains the sso flow line (metadata_list.yml; design-records folds DESIGN.md); TEAM-M6-05's NetworkSsoFlowStore gets its Redis implementation, installed in production.

Questions: `team-m2-16-sso-flow-state-row.md`.

### QD-721: Should EvsRepo's write take the path version its caller read, so a mail writer's append is a path CAS?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §11 Encrypted versioned storage.*

EvsPathWrite gains IfVersion *uint64 (nil: as today), which planPath checks against what its read found (0: absent or removed; else the standing version), answering the same EvsError PATH_CONFLICT a racing commit gets when they differ; the push's base_entry_version then equals the caller's read, so §11.8's 5g CAS spans the caller's read to the commit. It gives §15.7's created-only-if-absent writes (addr/, burner/, o/, ingest's m/) their create-only form as IfVersion 0. mailEvsStore.Write maps each write to one EvsPathWrite and PATH_CONFLICT's token paths back to its own paths, and every mail writer reads again on a conflict, as MAIL-M7-06 built.

Changes: EvsPathWrite.IfVersion and planPath's check (evs_plan.go, an EVS1 change); mailEvsStore.Write wired to it, so MAIL writes through evs (MAIL-M7-04, -06, -12, -15).

Questions: `mail-m7-06-evs-path-precondition.md`.

### QD-722: Does a record-class stream's creates-only rule take a directory delta that only adds names, so §16.8's 2,048-entry directories can grow, or does a stream carry no directory rows at all?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §11 Encrypted versioned storage.*

On a record-class stream ref, evs's creates-only rule (5c's checkCreatesOnly and replaying readers' createsOnly in evsCheckRefRules) accepts a directory change whose delta only adds rows: no removed tokens, on the directory entry's newest version, the entry staying of kind directory. Every file change stays a creation. §16.8's storage row and RECORD.md section 5.2 stand as written (2,048 entries to a directory, its name table within 256 KiB), and §11.8's record-class row reads "creates only, a directory taking add-only deltas". Each push into a standing leaf rewrites that directory's folded index entry, up to 256 KiB, as §16.8 sized. RECORD-M3-12's binding needs no change once evs takes the delta.

Changes: §11.8's record-class refs row (design-records); evsservice/check_refs.go's checkCreatesOnly and evs_verify.go's evsCheckRefRules take an add-only delta; RECORD-M3-12's local refusal (ErrEvsStreamDirectoryDelta) goes.

Questions: `record-m3-12-stream-directory-rows.md`.

### QD-723: How does a members endpoint on port 8443 sign its visitors in, when the issuer takes an edge origin only with no port?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §7 Networks, teams, members, enrollment, and SSO.*

§7.8's edge login issuer (TEAM-M5-01's server/oauth/edge_login.go) accepts client_id https://<host>.<net>.<root>:<port> for the four tlsedge ports, 443 written bare, with redirect_uri on that same origin and the ID token's aud that origin, and checks the members publish grant for (host, port), which ACL-M5-01's PublishGrant(subject, host, port, now) already takes. Each endpoint stays its own origin and audience (D-TEAM-15's one origin), so a 443 session never counts on 8443 or the reverse, and the TLS front logs members in on every tlsedge port. §7.8's wording says the origin carries its port when it is not 443.

Changes: §7.8's edge login wording (design-records); TEAM-M5-01's issuer accepts the tlsedge ports and checks the grant for (host, port); the TLS front's members login on non-443 ports (tls_edge_login.go) stops answering 503.

Questions: `tls-m5-19-members-login-on-8443.md`.

### QD-724: Where does api keep devices' re-seed uploads until two members agree, and how does it know a network's log has resumed?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §7 Networks, teams, members, enrollment, and SSO.*

api keeps §7.9's site-loss re-seed uploads in a Redis soft-state family {acl_<networkId>}r: one hash field per uploading sidecar holding its newest upload, the key's ttl 24 h, and a resumed marker field set when the network's resume base lands. Uploads are soft state devices send again until their network resumes, which owner decision 136 lets Redis hold, so they adopt across api instances. §7.8's re-seed mode ends per network at the resumed marker, while sidecar.yml's reseed stays the switch that allows it at all. §2.8's api-7 gains the family's line. The ttl is a settings field with 24 h as its default (QD-702).

Changes: §2.8's api-7 gains {acl_<networkId>}r (metadata_list.yml; design-records folds DESIGN.md); model.ConfigReseedUploads moves from process memory to the Redis family; re-seed mode ends per network at the resumed marker.

Questions: `team-m3-02-reseed-upload-store.md`.

### QD-725: What does `POST /evs/v1/repos/<id>/reseed` take, and which of a push's checks does a re-seeded push skip?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §11 Encrypted versioned storage.*

POST /evs/v1/repos/<id>/reseed takes one message, EvsReseedRequest {statement = 1, payload = 2, parts = 3 (repeated EvsPushPart bytes, in order), slot_id = 4, slot = 5}, one push or one slot per call. evs runs the push route's steps 4 to 8 in a reseed mode that writes an EVS_BATCH_RESEED record per push, and per part beside the seal record for a push in parts. The mode skips the statement's time window and TIME_STALE, the 24 h receipt rule and the quota gate (QD-084 leaves re-seed uploads unbilled), and keeps the chain onto the current head (base_version and base_chain equal to it, so only versions past the head go), the signature at the statement's own auth pin, §11.8's refs table and 5h's slot rules. It takes segments only once PUT seg/ holds them (EVSB-M2-09), and a slot only once a re-seeded version names it, stripped by every ERASE evs holds (QD-096). Signed EvsReseed statements are kept at reseed/<repo>/<ref> and served with the head, which is how a reader's AcceptReseed gets them. §11.13's ordering and refusals stand as written. §2.8 gains the reseed/ object family's row.

Changes: evs.proto's EvsReseedRequest (fenced by design-records); §2.8's row for reseed/<repo>/<ref> (metadata_list.yml); EVSB-M2-20's route, EvsRepo.Reseed, ur evs reseed and FS-41's storage clauses build on it.

Questions: `evsb-m2-19-reseed-route-body.md`.

### QD-726: What bytes does a sealed §21.10 record carry, and where in vault do its seal key and MAC key live?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §21 Abuse, safety, and legal process.*

A §21.10 record is sealed with HPKE-XWing as smtpedge's sealed report copies are (QD-441: KEM 0x647a, HKDF-SHA256, AES-128-GCM, base mode), info "UR abuse 1.0 record", body u8(1) || enc (1,120 B) || ct, the record's canonical JSON with its HMAC-SHA-256 MAC (QD-078) inside the plaintext. Vault file abuse-mailbox.yml holds abuse_mailbox_mac_key (32 random bytes, base64) and abuse_mailbox_seal_public_key (1,216 B, base64), mounted on api and taskworker only; the private key is held offline beside §19.10's restore runbook and is reachable by no running service. The mail is a text/plain body of the base64, through api's and taskworker's SES path. The legal-request mailbox (QD-088) takes the same seal and key file.

Changes: the production AbuseRecordMailer seals and sends (ABUSE-M5-03, -05); the owner creates abuse-mailbox.yml in vault and keeps the private key offline (an outward action).

Questions: `abuse-m5-03-record-seal.md`.

### QD-727: How does a verifier holding only rows check a decision's channel against evidenceDefault, for an action no requests rule governs?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §8 Access control.*

AclRows gains repeated uint32 evidence_default = 10: the policy document's effective evidenceDefault (all three channels where the document names none), compiled at each base as each AclRequestRule's evidence list is (QD-396). Every verifier, the daemon, every server gate and every reader, checks a ruleless action's channel against it in §16.6's spendable: dns_set and dns_delete at POST /dns/records (§12.8) and bridge_expose approvals in ConfigState.CheckBridgeApproval. §2.8's api-7 names the field, since rows are server-visible (I-18); it shows api only which channels the network accepts by default, as each rule's row already does for grants. One spend check and one verdict everywhere (D-MCP-12), and a document's narrowing of evidenceDefault (to device alone, say) holds at the gates.

Changes: AclRows.evidence_default = 10 (acl.proto; fenced by design-records); §2.8's api-7 names it (metadata_list.yml); SpendState reads it for a ruleless action, replacing SpendRefusalEvidenceUnknown's interim refusal.

Questions: `mcp-m3-03-evidence-default-at-gates.md`.

### QD-728: Which {svc_} key CreateContract reads for a ur/ stream, where the edge is the listener and the sidecar the dialer?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §6 The sidecar subprotocol.*

§6.10.1 item 3's service pair is keyed by its non-edge end in every namespace: a ur/ Find (SOCK-M9-01, D-SOCK-11), where the edge listens as ur/<service> and a sidecar dials, writes field <edge listener client_id> of {svc_<sidecar dialer client_id>}, the roles swapped in the key and the ticket unchanged, so CreateContract's one Redis read is always field <edge> of {svc_<sidecar>} whichever end listens. Revocation and unlisten remove a ur/ pair from the dialer's key; the edge's last unlisten does not reach it, so a ur/ pair ends at its 60 min ttl. §6.10.1 item 3 and §2.8's sock-3 say so.

Changes: §6.10.1 item 3 and §2.8's sock-3 (design-records); SOCK-M9-01's Find writes a ur/ pair under the sidecar dialer's key; CreateContract's decideServiceContract reads field <edge> of {svc_<sidecar>} for ur/ streams too.

Questions: `proto-m5-04-ur-pair-key.md`.

### QD-729: Which SidecarActionKind and CanonicalAction fields carry §14.4's TL4 allowance for a recipient domain?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §14 The SMTP edge.*

§14.4's TL4 allowance for a recipient domain is its own outward action (I-8): SidecarActionKind 18, mail_tls_unauthenticated, appended to record.proto's enum, whose row in record_action_kinds.go requires host (5) holding the recipient domain, lowercase with no trailing dot, and takes expires_millis (8) for an allowance that ends. Approvers render it from daemon-built fields as "Send mail to <domain> through a mail server that cannot be authenticated: an active URnetwork edge could read it" (§2.8 EX4). The desktop keeps a granted allowance per recipient domain in its SidecarStore, and a phone's message carries the approval's id on its signed o/ entry's tl4_domains (plan-SMTP-small-readings #11). No ordinary mail_send approval counts as TL4 consent. §5.4's list and §16.8's table gain the kind.

Changes: record.proto's SidecarActionKind 18 (fenced by design-records); §5.4's and §16.8's lists (design-records); SmtpTlsPolicy.AllowUnauthenticated authorizes through it.

Questions: `smtp-m9-06-tl4-allowance-action.md`.

### QD-730: What does `KeyRegister.attestation` hold, given that every attestation format but `none` signs the create ceremony's client data, which the attestation object does not carry?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §16 The local MCP server and record primitives.*

KeyRegister.attestation holds a canonical CBOR map of two byte strings, {"attObj": the WebAuthn attestation object, "clientDataJSON": the create ceremony's client data}; a CTAP2 client (ur with a FIDO key) writes the JSON it hashed. The verifier (MCP-M3-08's VerifyPresenceAttestation) checks the client data's type is webauthn.create and its origin is on §16.6's table, checks each of packed, tpm, android-key and apple over SHA-256 of the client data against the roots the release pins, and leaves the challenge unchecked, since the credential key in authData, which must equal public_key, binds the attestation to the registration. fmt none and an empty attestation still label asserted. §16.6 gains the line, and api-7's words for what a key registration shows name the origin and the challenge. QD-137's interim (clients request none, no production roots) stands until roots ship.

Changes: §16.6's registration row and §2.8's api-7 wording (design-records); VerifyPresenceAttestation reads the map and checks the four formats over the client data.

Questions: `mcp-m2-01-attestation-client-data.md`.

### QD-731: Should an AuthKeyBundle's delegation_id be the 32-byte SHA-256 of the Signed Delegation that the log names, rather than the 16-byte id TEAM-M1-05's parser reads?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §7 Networks, teams, members, enrollment, and SSO.*

An AuthKeyBundle's delegation_id is the 32-byte delegation_id §10.5 defines, SHA-256 of the Signed Delegation (bridge.SignedBytesSha256 per QD-001), the one identifier ConfigState's DelegationRow, §6.9's signer table and the daemon's self-signed SidecarAdmit (signer_id the delegation_id, §5.6, C-03) already use. TEAM-M1-05's decodeAuthKeyBundle checks 32 bytes and keeps them as bytes, and the creating device's encoder writes them. §7.8's AuthKeyBundle line gives the width. No key has been minted, so nothing migrates.

Changes: §7.8's AuthKeyBundle line names 32 bytes (design-records); TEAM-M1-05's decodeAuthKeyBundle and the creating device's encoder.

Questions: `core-m2-01-bundle-delegation-id-width.md`.

### QD-732: Where does the keyless device role get the base, rows and entries that verify a BridgeState, when §18.6's `SetState(state)` takes the state alone?
*Decided by the owner on 2026-11-12, asked one question at a time, then withdrawn. Folds into §18 SDK, apps, and extension integration.*

Withdrawn and corrected on 2026-11-12: DESIGN-DETAILS.md section 4 had answered this before it was asked, and the owner confirmed that section 4 stands. Under owner decision 197 the apps' VPN component is self-contained with its own forwarding key and never waits on the app, so it fetches the log itself: the newest base, its rows and the entries a BridgeState rests on are in its own store, and device.Posture.SetState(state, log) keeps the argument SDK-M4-01 built, filled in process. Nothing new crosses the app-to-component channel, and §18.6's SetState(state) and §17.8's persist row read as section 4 writes them. The answer first given (the log travelling with each state over SDK-M8-07's channel) does not stand.

Changes: none; DESIGN-DETAILS section 4 stands as written.

Questions: `sdk-m4-01-state-proof.md`.
### QD-733: Where in BridgeRules do `autogroup:untagged`'s rows live, which an sdk provider gives a sealed subject that no row binds?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §17 IP addresses, subnet routing, and port forwarding.*

BridgeRules gains BridgeRuleSubject untagged = 10: the dial, route and exit rows autogroup:untagged holds at this host, with no sidecar_id, member_id or client_ids. An sdk provider before C16 gives those rows to any sealed subject no row binds (an other client, §8.4, untagged for rule 4 as owner decision 105 keeps for app devices), so under an ACL document an app device keeps the exits its policy grants the group. The compiler (BRIDGE-M4-16) fills it from §8.5's expansion; ParseBridgeRules checks it as a subject's rows. Per-subject rows stay as they are, and every such client still shares the zero subject id in its rule tags. BridgeRules is in-process, so no §2.8 row.

Changes: bridge.proto's BridgeRules.untagged = 10 (fenced by design-records); BRIDGE-M4-06's parser and fixture, BRIDGE-M4-16's compiler and BRIDGE-M4-09's hook use it.


DESIGN-DETAILS 12.9 had answered it on this option (BridgeRules.untagged = 10, filled by the compile's reach pass), and section 12's tasks built it; this confirms it.
Questions: `bridge-m4-09-other-client-rows.md`.

### QD-734: How does the push that creates a ref give evs the head's sealed ref name and, for an overlay, its base (ref, version)?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §11 Encrypted versioned storage.*

A push that creates its ref, or the first push after a DELETE, carries two payload sections: 15, the sealed ref name, and 16, the overlay base (an EvsOverlay {ref_id, version}). The same two values are repeated inside the push's sealed metadata, so the push's signature covers them through sealed_metadata_sha256. The sealed name uses manifest of the push's generation with AAD "UR evs 1.0 ref name" || repo_id || ref_id. evs copies the two cleartext sections into EvsHead's sealed_ref_name (7) and base (8) at step 7 and refuses them on any other push with 409 REF_MODE; a reader compares the head's cleartext copies with the sealed ones and alarms on a mismatch. §11.7's versions row reads the overlay chain from the head at creation. No fenced message changes; EVS-FORMAT.md states both sections.

Changes: EVS-FORMAT.md's payload sections 15 and 16 and the sealed metadata's copies; evs's step 7 fills EvsHead.sealed_ref_name and base; readers check them; GET .../refs lists refs by name and overlays can be created.


DESIGN-DETAILS section 8 had built on this option, and section 8's tasks built it (evs_ref.go's ref name AAD); this confirms it.
Questions: `evs1-m2-01-ref-creation-fields.md`.

### QD-735: Does an inline record travel inside its entry version's locator, or in the payload's inline-records section, or both?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §11 Encrypted versioned storage.*

An inline record travels inside its entry version's kind-2 EvsLocator (inline = 5), so entry_sha256 covers its bytes and there is one copy. In format 1 the payload's inline-records section (3) and EvsPushPart.inline_records (5) stay empty: evs refuses a push or part that sets either as INVALID, and both are held for kind 3's push-payload range, which §11.6 reserves for a format readers learn first. idx/ keeps the newest version with its inline records and older ones with them elided, and evs restores them from the push record's entry versions before serving the signed bytes, as §11.7's holds row says; §11.9 serves a dropped version's entry only when its chain names no inline record. Nothing renumbers. EVS-FORMAT.md's interim already reads so.

Changes: EVS-FORMAT.md's interim reading becomes the rule; EVS1-M2-05's codec, EVS1-M2-10's elision and restore, and EVS1-M2-11's 5h check of kind-2 locators build on it.

Questions: `evs1-m2-01-inline-record-home.md`.

### QD-736: Where does an open AuthorityProposal live once a base folds past it, given ProjectionRows has no field for one?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §7 Networks, teams, members, enrollment, and SSO.*

ProjectionRows gains repeated ProposalRow proposals = 7: each AuthorityProposal still open at the base (proposal_id, the statement type, the proposed statement's bytes or its hash, each signer with its position, the proposal's not_after_ms, and for a recovery-signed proposal its p and o), compiled from the config head's fold records like every other row. A proposal folded under a base stays open in the rows and closes at its k-th counted cosign, its recovery window's ApiTick (72 h after its newest recovery signature) or its not_after (7 days), so api, the gates, a new device and a long-running reader hold the same S(n) after a fold (D-TEAM-19). §2.8's api-7 gains the line; proposals are log statements api already sees, so no value is new to it. Rows grow only by open proposals.


Changes: none beyond DESIGN-DETAILS section 5 as built. DESIGN-DETAILS section 5 had answered it on this option (ProjectionRows.proposals = 7, ProposalRow), and TEAM-M2-05 built it; this confirms it.

Questions: `team-m2-02-open-proposals-across-bases.md`.

### QD-737: Which record lists a push in parts' purge candidates, when a rename's removal and its target can sit in different parts?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §11 Encrypted versioned storage.*

For a push in parts, no part's record lists purge candidates; the seal's record lists the push's candidates: each part's replaced versions' kind-5 segments and, in slot-keyed repos, their slots, less every segment and slot any part's versions name. The seal computes them where every version is known, from its rerun of step 4 over the heads and entries (or from what the part records carry of each replaced version's kind-5 ids and slots), through evsservice.PurgeCandidates unchanged. A one-part push lists its candidates in its own record as before. §11.13's purge row says "in the record of the push, or for a push in parts of its seal". plan-EVS2-slot-rename's rule that a removed path's segment or slot is named by at most one new version, checked across parts at the seal, stands.

Changes: §11.13's purge row (design-records); EVS2-M10-06 lists a push in parts' candidates at the seal, not per part.


DESIGN-DETAILS 10.9 had answered it on this option, the part's record carrying what it replaced so the seal reads no entry again, which governs; EVS2-M10-06 built it.
Questions: `evs2-m10-04-purge-across-parts.md`.

### QD-738: How does a DROP whose lists need more parts than its changes fill span parts, when every part must hold a change?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §11 Encrypted versioned storage.*

In format 2, a DROP push's parts after its last change may hold no change and only sections slices of its lists (plan-EVS2-drop-list-parts). Such a part has no changes_root field and joins no Merkle level; part_count counts it and parts_sha256 binds it; the statement's changes_root covers only the parts with changes, and the parted tree and absence proofs name changed parts only. Changeless parts come only after the last changed part, and only in a DROP. One DROP per action stands, as §11.7 writes it. It agrees with QD-658, under which a statement in parts may state an empty change list. EVS-FORMAT.md's parts row says so for format 2.

Changes: EVS-FORMAT.md's format 2 parts and seal rules; EVS2's DROP builder and evs's part and seal checks.


DESIGN-DETAILS 10.9 had answered it on this option, which QD-601 and QD-658 since made the rule for every push; 10.2.5 is the DROP's layout and EVS2-M10-36 built it.
Questions: `evs2-m10-03-drop-list-parts-without-changes.md`.

### QD-739: Where does a record entry's 32-byte salt live in its slot, when evs's slot format holds only 72-byte wrapped 32-byte keys?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §11 Encrypted versioned storage.*

EVS-FORMAT.md adds a 104 B wrapped block for record-class slots: 24 B nonce, the 64 B row of the entry's 32 B key || its 256-bit salt, 16 B tag, wrapped under fek_g with its own AAD label ("UR evs 1.0 record slot row" || repo_id || u64be(g)). evs's checkEvsSlotObject accepts 72 B, 104 B or the deposit's HPKE length, one width per slot. The key and salt die together in one ERASE (owner decisions 61 and 90), and neither sits in the entry file. §16.8 and RECORD.md sections 5.1 and 5.2 stand as written; §11.8's slot/ row names both widths. evs still opens nothing (I-1).

Changes: EVS-FORMAT.md's wrapped-key block gains the 104 B record row (before format 1 freezes); §11.8's slot/ row (design-records); evs_slot.go's checkEvsSlotObject and codecs accept it; RECORD-M3-01's sealing and RECORD-M3-12's binding write real slots.

Questions: `record-m2-01-slot-row-salt.md`.

### QD-740: How do protos-services-canonical-action's move of local_port, weight and alpn and plan-BRIDGE-gate-row-prefixes#2's sealed_detail combine in record.proto, and which CanonicalAction version does sealed_detail take?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §16 The local MCP server and record primitives.*

QD-064 and QD-003 combine by field. local_port, weight and alpn leave CanonicalAction (24, 25 and 34 reserved) for sealed ApprovalRequest fields 14, 15 and 16, daemon-built and rendered by approvers, for every kind that has them (socket_listen, tls_publish, bridge_forward, bridge_expose), since none is a grant's prefix or port; publishes keep their other clear fields. sealed_detail = 38 belongs to dial and route grants, as CanonicalAction version 4: a new record.proto message CanonicalActionDetail { repeated string cidrs = 1; uint32 target_port = 2; repeated string grant_dst = 3; } under plan-TEAM-sealed-field-format's SealedBody, and those grants' clear fields then hold no prefix or port. A version-3 access_request to a worker's ports carries its port and sidecar:<id>:tcp:<port> text the same way in field 38, so version 3's clear set leaves 27 and port text out. CanonicalActionVersionKnown gains 4, and ParseStoredCanonicalAction names field 38. record.proto, MCP-M3-02's kind table and testdata/metadata/fields.yml change together once design-records writes §16.8's fence.

Changes: §16.8's CanonicalAction fence: 24, 25, 34 reserved, sealed_detail = 38, version 4, CanonicalActionDetail (design-records); ApprovalRequest 14, 15, 16; MCP-M3-02's kind table and testdata/metadata/fields.yml.

Questions: `record-m2-01-canonical-action-detail.md`.

### QD-741: Does §2.8's cert-1 cover two values network_tls_cert must hold between steps: an issued chain, and a pending revocation's reason?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §2 Trust model and threat model.*

§2.8's cert-1 sees gains "issued chains until 30 d after expiry or revocation, and a requested revocation's reason", a list version bump in §2.8 and metadata_list.yml. TLS-M5-16's store keeps a URnetwork-zone row's issued chain, which GET /tls/cert-order/<id> answers after a restart or to a device that was offline, and TLS-M5-16 and TLS-M5-17 carry a requested revocation's reason (keyCompromise from POST /tls/cert-revoke, cessationOfOperation for §21.6's takedowns) in the row until the sweep's revocation reaches the CA. Neither value adds anything a CT log (cert-2) or a CA's CRL does not already publish. The 30 d is a settings field with that default (QD-702).

Changes: §2.8's cert-1 and metadata_list.yml (a list version bump); TLS-M5-16's store gains the chain and reason columns; TLS-M5-17's sweep revokes with the stored reason.

Questions: `tls-m5-05-cert-row-values.md`.

### QD-742: When does a revoked or failed network_tls_cert row's 30 days start, given cert-1 names no time for either?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §2 Trust model and threat model.*

network_tls_cert gains state_time timestamp NOT NULL, set with every state change, in MG5's CREATE while the group is pending (so no running release sees a migration), and §2.8's cert-1 sees gains "the time of its latest state". cert-1's ttl reads "30 d after expiry, revocation or failure": CertsStore's purge (and TLS-M5-17's) reads not_after for an expired row and state_time for a revoked or failed one. §13.8's budget rebuild of a lost {tcb_} key may read an order's admission from it. If M5's Gn-out came first, it would list this open; it no longer needs to.

Changes: §2.8's cert-1 sees and ttl (metadata_list.yml); network_tls_cert.state_time in MG5's CREATE; CertsStore.PurgeEnded and TLS-M5-17's purge read it.

Questions: `tls-m5-14-cert-row-end-time.md`.

### QD-743: Should AclRepo's folded access log carry the RepoDelete's entry time and each removed admin's position, which readers need once those entries leave retention?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §8 Access control.*

AclRepoDeletionRow gains int64 deleted_time_ms = 5, the RepoDelete entry's time_ms, and AclRepoAdminRow gains uint64 removed_at = 4: a RepoAdmin{remove} keeps the admin's row stamped with the removal's position instead of deleting it, until the next base's compile drops rows past retention. Readers, evs and taskworker then judge from rows alone: a RepoRestore within 7 days of a RepoDelete without now (§8.8) on any day of the window, taskworker's shred at 7 d 10 min after the RepoDelete's entry (§11.12), and a removed admin's right at a position before its removal (AclState.RepoAdminAt). Both values are already server-visible as their entries' times and positions, so §2.8's api-7 changes only in wording. Two additive fields before acl.proto freezes at M2.

Changes: acl.proto's two fields (fenced by design-records); §2.8's api-7 wording (metadata_list.yml); ACL-M2-06's RepoRestore judgment, AclState.RepoAdminAt and taskworker's shred timing read the rows.

Questions: `acl-m2-06-access-log-positions.md`.

### QD-744: Should §19.6's rule (3) hold a failed DELETE's key until every commit of it has answered and been reverted, since TLC finds two DELETEs on one key breaking FI-30 under the rule as written?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §19 Server services.*

§19.6's rule (3) holds a failed DELETE's key until every one of its drive commits has answered and each that landed has been reverted, with no revert after release; a failed PUT keeps rule (3) as written (released once the drives that may still hold it number under N/2). Nothing of a failed DELETE then lands or reverts once another request can see the key, so FI-30's NoStaleQuorum holds for two DELETEs on one key, which §11.7's marker collection, v1's purge and the drop job rely on. The cost, a DELETE whose commit stalled on a frozen host holding its key until that host answers or its drives are replaced, is paid only by background jobs' unconditional DELETEs; D-OPS-20's Why and FI-30's last clause say so, with section 2's per-commit stamp (DESIGN-DETAILS 2.4, 2.8). The in-house MinIO build already holds a failed DELETE so (EVSB-M2-22, minio e7539a6e5).

Changes: §19.6's rule (3), D-OPS-20's cost and FI-30's last clause (design-records, with DESIGN-DETAILS 2.8's text); StoreSettle.tla models the held DELETE and passes TLC with DELETEs in the run (M2's Gn-in).

Questions: `evs-models-settle-stalled-deletes.md`.

### QD-745: How should api's activation tick learn which recovery windows end, now that DESIGN-DETAILS.md section 5 moves open proposals into ProposalRow?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §7 Networks, teams, members, enrollment, and SSO.*

api schedules an activation by a run-once task per proposal, as TEAM-M2-14's plan reads, on DESIGN-DETAILS section 5's ProposalRow (TEAM-M2-05): after each statement append, for each proposal whose window moved at that entry, RunOnce("config_log_activation", proposal_id) at its window_time_ms + 72 h; when it runs it checks the row at the tip (still open, its kind, its counted signatures, its window time) and appends an ApiTick naming the activation, which configCheckTick judges from the row at every reader. ConfigState exposes the open proposals with their kind and window_time_ms (5.7's PendingProposals and RecoveryWindow). One more taskworker target; nothing in the wire changes. No periodic sweep.

Changes: TEAM-M2-14's activation ticks on ProposalRow; a config_log_activation run-once taskworker target; api's checkConfigLogTick and the sidecar verifier accept an activation judged from the row.

Questions: `team-m1-04-activation-ticks.md`.

### QD-746: How does every verifier learn that a base's own config head shrank a repo's key holders, when a new device and a cold gate start at that base?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §7 Networks, teams, members, enrollment, and SSO.*

ProjectionHeader gains repeated bytes shrunk_repo_ids: the repos whose key holders the base's own config head change shrinks (KeyHolders(R, b-1, t_b) not a subset of KeyHolders(R, b, t_b)), computed by the writer from S(b-1) and S(b). A verifier present at b-1 recomputes it and forks on a difference, as with tail_verdicts; a new device or rows-only gate that starts at b (DESIGN-DETAILS 5.2.4's StartAtBase) takes it, so every verifier sets AclRepo.holders_shrunk_at = b for exactly those repos (D-TEAM-19). §2.8's api-7 gains the line. The interim fail-closed rule (a policy change at a base shrinks every repo) goes once the field lands.

Changes: config.proto's ProjectionHeader.shrunk_repo_ids (fenced by design-records); §2.8's api-7 line (metadata_list.yml); TEAM-M2-17's holders_shrunk_at at a base reads it; the every-repo interim goes.

Questions: `team-m2-09-base-shrinks.md`.

### QD-747: How does a writer leaf other than the uploader learn that an epoch's Welcome was never written, so it can remove and re-add the joiner after 10 minutes?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §10 Group keys for evs: MLS and the GKM service.*

gkm answers whether an epoch's Welcome stands: HEAD /gkm/groups/<group_id>/welcome/<n> under rw, 200 or 404 with no body. A writer leaf that adopted an Add at epoch n asks once after GkmSettings.WelcomeTimeout (10 minutes) and, on a 404, removes and re-adds the joiner in one commit (GkmPendingChanges' Unwelcomed, which CheckCommit accepts), so §10.6's re-add fires for any writer leaf, not only the epoch's uploader. It discloses nothing beyond gkm-5's Welcome objects, whose keys every reader can compute; a false 200 leaves the joiner waiting as today and a false 404 costs one Remove and Add. §11.20's or §10.6's route list gains the route.

Changes: gkm's HEAD welcome route (§10.6 route list, design-records); the engine passes Unwelcomed leaves for epochs another leaf uploaded (KEYS-M2-21).

Questions: `keys-m2-19-welcome-timeout-evidence.md`.

### QD-748: When a repo is created with --private in a team network whose directory does not exist yet, how does it stay private once the directory appears?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §16 The local MCP server and record primitives.*

A repo-creating command run with --private in a team network that has no directory refuses before filing the RepoCreate, naming the missing directory; where the device is a directory admin it files the directory first and then creates the repo with its private marker. So every private repo has its marker, and §16.11's predating rule stays as written: a general or record repo that predates the directory is announced by the first of its admins' devices to sync it (owner decision 181's every repo by default). RECORD-M6-15's interim, writing a private marker for every predating repo, goes once the refusal lands.

Changes: §16.11's private row gains the refusal (design-records); the repo-creating commands refuse --private with no directory; RECORD-M6-15's predating rule announces again.

Questions: `record-m6-14-private-before-directory.md`.

### QD-749: May evs write {evsc_<client_id>} before §2.8's evs-8 row names the family, as plan-EVS1-subscription-caps#2 decided?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §11 Encrypted versioned storage.*

QD-263's {evsc_<client_id>} lands row first: evs-8's store line in metadata_list.yml gains it in QD-263's words (a sorted set of a client's repo ids scored by last subscribe or renewal, soft state), with §19.7's tags, D-OPS-16's rdb filter and §11.10's slots row for design-records to fold into DESIGN.md; then evs builds the key and its script, checked before the lease script, so evs_repos_per_client's 500-repo cap applies on POST /evs/v1/subscriptions. The schema guard stays as it is (I-18).

Changes: evs-8's store line in metadata_list.yml; §19.7's tags, D-OPS-16's rdb filter and §11.10's slots row (design-records); {evsc_} and its cap script in evs's subscriptions route.

Questions: `evs1-m2-15-evsc-metadata-row.md`.

### QD-750: Where does an operations command that reads Postgres live, given that sidecarctl, a module of the sidecar repo, cannot link any server package under §4.7's license and module rules?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §4 Repositories, code placement, branches, and build.*

sidecarctl moves from sidecar/sidecarctl to server/sidecarctl: still one binary for every operations command this build adds (C-23 and the owner's direction of 2026-11-07 keep their point; their path changes), beside the model code its commands call and under server's own dependency, license and layering rules, which let it link server's packages and the engine packages. The certs commands already landed in sidecar/sidecarctl move once, with their tests and check/'s sidecarctl rows. Then sidecarctl dns census is a thin command over model.CensusDnsNetworkNames behind server.RequirePgReadOnly(); sidecarctl evs purge-turn-on binds to server.CurrentSidecarConfig().Format2() and schedules evsservice.EvsSweepTurnOnTaskRequest() on the env's task queue (sidecarhost.NewTasks); dns restoring, dns restore and dns ceremony are short files over dnshost.NewRestoreStep and dnsservice's ceremony functions; and later commands that read the database (sidecar restore, network sidecar-limit, the abuse commands) go there too. OPS tasks write the commands, whichever lane runs them. Until the move lands, commands that need server or an engine stay refusing or unbuilt, as built.

Changes: C-23's path and the brief's sidecarctl rule (server/sidecarctl); sidecar/sidecarctl moves to server/sidecarctl with its tests and check/'s rows; dns census, evs purge-turn-on, dns restoring, dns restore and dns ceremony are built there.

Questions: `dns-m0-01-sidecarctl-server-link.md`, `ops-m10-01-purge-turn-on-links.md`, `dns-m5-15-dns-ops-commands.md`.

### QD-751: Should certs renew stay on lego v4.35.2, the release certs issue runs, until someone checks lego v5's CLI, given that D-OPS-12 names v5 and v5 rejects the flags both commands pass?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §19 Server services.*

sidecarctl certs renew and warpctl certs issue stay on goacme/lego v4.35.2, the release production runs, with certs issue's exact flags plus --server, held together by TestCertsRenewLegoArgsAreTheImagesCli and TestCertsRenewRunsTheLegoReleaseCertsIssueRuns; D-OPS-12's lego v5 is recorded as the target. The move to v5 is one change to both commands and both tests, made once someone allowed to fetch the image has read v5's --help or run one order against Let's Encrypt staging (an outward action outside this run). Meanwhile renewals send no RFC 9773 replaces, which costs the CA's rate-limit exemption for a renewal it asked for and does not change when a certificate renews; sidecarctl reads ARI itself.

Changes: D-OPS-12 names v5 as the target, v4.35.2 as what runs (design-records); the v5 move is an owner or ops action outside this run.

Questions: `ops-m5-07-lego-v5.md`.

### QD-752: Where does QD-128's competition migration live on server's `sidecar` branch, and in how many steps?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §19 Server services.*

QD-128's competition migration lands in two steps. The permissive step, replacing competition_v2_source_graph_valid and competition_v2_source_authorized so a source graph of ten keys, or of eleven with sidecar, passes, goes in MG0's pending part (db_migrations_sidecar_pending.go) and registers with MG0 at M0's Gn-out; with it land server's Go list of eleven, its digest and the evaluator scripts. The tightening step, requiring eleven, is a cleanup migration once every competition job runs a release that sends eleven, as connect/CODESTYLE.md's additive-then-cleanup order says. §19.7's MG0 row gains the competition entry, and TestSidecarGroupsAreAdditive admits a function replacement that only widens a guard. Evaluator images are rebuilt from the Gn-out's commit; that rebuild and the cleanup's deploy are outward steps outside this run.

Changes: §19.7's MG0 row gains the competition entry (design-records); the permissive migration in MG0's pending part, with server's Go list, digest and evaluator scripts; TestSidecarGroupsAreAdditive admits a widening function replacement.

Questions: `wire-consumers-competition-migration-home.md`.

### QD-753: Who builds the two file-cluster signal sources monitor reads that no task owns: the minio fork's heal-debt export, and a scrape of each cluster's MinIO node metrics into Mimir?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §19 Server services.*

Both file-cluster signal sources get builders. A minio task builds the fork's half of QD-035: er.addPartial sets SetIndex and PoolIndex, cmd/mrf.go exports per pool and set the partial-write queue's depth, its dropped entries and its unclean starts, and the fork exports a last-full-heal time per cluster, so §19.6's degraded and at_risk can end when a full heal ends; monitor exports them as urnetwork_filecluster_mrf_depth{cluster,set} and the two counters, and EVSB-M3-01's fileClusterStateProbe.healDebt reads the queue. An xops task grows EVSB-M2-04's playbook-file-clusters.yml with a fluent-bit prometheus_scrape of each cluster's MinIO node metrics (/minio/v2/metrics/node) with a bearer token from vault, add_label cluster <id> and job file_cluster_minio, which SIGNALS.md §29.3's contract and filecluster-settle read from Mimir. Until both land, the owner's interim stands: heal debt reads unknown, never zero.

Changes: a minio task: the fork's partial-write queue export and last-full-heal time; an xops task: the node-metrics scrape in playbook-file-clusters.yml; monitor's queue reader in fileClusterStateProbe.healDebt.

Questions: `evsb-m3-01-file-cluster-signal-sources.md`.

### QD-754: How do §19.8's business-hours pages reach the rota, when the pager pages only at any hour?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §19 Server services.*

§19.8's business row pages the rota in business hours: OPS-M3-01's pageClasses rows gain an hours field, any or business, and PagerAlertNotifier holds a business-hours page until the business calendar opens (model's AbuseCalendar, abuse.yml's review hours, or a pager-service schedule when one is chosen), then pages, and resolves it as usual, with the pager's dedup and retry unchanged. A page whose alert resolves before the calendar opens is dropped. The business rows join by a table row each: filecluster-drive-dwpd-business, filecluster-drive-rating-short, a cluster's projected exhaustion within its move tool's lead time or at its cohort limit, a segment cluster's hdd crossing (g0-recheck-0-hdd-trigger #1), and an NS failing an hour (plan-DNS-running-ns, DNS-M5-17's).

Changes: OPS-M3-01's pageClasses rows gain hours; PagerAlertNotifier holds business pages until the calendar opens; the business rows move from Slack warns to pages.

Questions: `evsb-m3-01-business-hours-pages.md`.

### QD-755: MLS hands its 12-byte AEAD nonces to testHookSecret, which the privacy capture refuses as findings: should mls_* stop hooking nonces, or should the capture search a 12-byte secret?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §22 Testing and verification.*

The MLS subset stops passing its 12-byte AEAD nonces to testHookSecret: mlsCipherSuite.expandWithLabel (mls_ciphersuite.go) takes a hook flag, false for the three nonce derivations RFC 9420 makes (ratchet_nonce in mls_secrettree.go, sender_data_nonce in mls_secrettree.go, welcome_nonce in mls_keyschedule.go), and every secret a nonce is derived from stays hooked. The privacy capture's rule stands: a secret under 16 bytes is refused as a finding, so no test passes on a value it could not search for (TEST-M1-05). §22.4's 'at every key creation, derivation and unwrap' reads keys, which a nonce is not.

Changes: the MLS subset's nonce derivations unhooked (mls_ciphersuite.go, mls_secrettree.go, mls_keyschedule.go); TEST-M2-11's S3a and S4a run whole under sidecar_testhooks.

Questions: `test-m2-11-mls-nonce-hooks.md`.

### QD-756: On a one-process cluster, the minio fork's settle build takes a DELETE past its deadline and crashes in its stash sweep: is a one-process cluster in scope, and whose fix is it?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §19 Server services.*

A one-process MinIO cluster is out of scope for production, since §19.6 builds every cluster from 4 hosts (owner decision 145's whole clusters): the in-house build refuses to start one in settle mode, naming the rule. Its nil lock server is fixed whatever the shape: (*localLocker).SettleRows and the stash sweep (settle-locks.go, settle-drive.go) never dereference a nil locker. T3's second metadata cluster, meta-2, becomes a 4 x 2 cluster like meta-1, so FS-63's second-cluster cases and EVSB-M2-17's suite run on a multi-host meta-2, and the suite's one-process path goes.

Changes: §19.6 says a cluster in settle mode has at least 4 hosts (design-records); the minio fork refuses a one-process cluster in settle mode and never dereferences a nil locker; T3's meta-2 becomes 4 x 2 (server/local/file-cluster-t3).

Questions: `evsb-m2-19-one-process-cluster-settle.md`.

### QD-757: Must a sidecar whose clock is 10 min off still renew and exchange its tokens, given that §7.4 holds a DPoP proof's iat within ±60 s of the api's clock?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §7 Networks, teams, members, enrollment, and SSO.*

A sidecar signs its DPoP proof's iat by the api's clock: it reads its offset from the Date header (or a server_time field) of its api answers, as §9.6's socket registrar reads the sockets service's, and signs iat at its own time plus that offset; a refusal for iat refreshes the offset once and retries. §7.4's ±60 s iat window and its replay ttl stay as they are, server-side and in sidecartest's fake api. §22.8's skew row's token clause then holds as written: a strict_exp sidecar 10 min fast or slow renews at GET /auth/refresh, POST /oauth/token's exchange and POST /network/auth-client. §7.4 gains the reading.

Changes: §7.4's proof row gains the reading (design-records); the sidecar's api client keeps the api's clock offset and api_dpop.go signs iat by it; TEST-M2-15's skew row token clause.

Questions: `test-m2-15-dpop-iat-under-skew.md`.

### QD-758: Should evs's client retry a segment PUT that the lb answers 502 or 504, which is what nginx gives a streamed PUT whose upstream died?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §11 Encrypted versioned storage.*

evs's client reads a 502 or 504 whose body is not an evs refusal as the lb's answer, no answer from evs at all: evsErrorOfAnswer (evs_http.go) marks it OutcomeUnknown, so EvsClient.retryRefusingNothing and the push sender send the same bytes again after ReadRetryWait, as they do for no answer, until §11.8's 200, 409 or 412. A streamed segment PUT cut by an lb drain then retries from the client and lands once, as §22.8's drain row says; the lb keeps streaming segment PUTs as OPS-M2-01 built it (no request buffering). The lb's own 502 after its two tries on a buffered path is retried the same way, which §11.8's retry row allows.

Changes: evs_http.go's evsErrorOfAnswer reads a non-evs 502 or 504 as no answer (EVS1-M2-26's); TEST-M2-15's client half of §22.8's lb drain row.

Questions: `test-m2-15-streamed-put-502-not-retried.md`.

### QD-759: Must server's api answer a request whose Postgres connection a restart cut with 503 and Retry-After, rather than its fixed 500?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §19 Server services.*

server's api answers a request whose Postgres connection a restart cut with 503 and Retry-After: 1, as it answers a lock timeout: RaiseHttpError (server/router/handler_utils.go) and the router's recover map the connection classes 08000, 08003, 08006, 57P01, 57P02 and 57P03 to 503, the cause staying in the log, so a client tells a restart from a failure that will repeat and §22.8's Postgres or PgBouncer restart row holds its retryable clause as written. A route whose effect may have committed before the cut keeps relying on its own idempotency (admin-token claims, sidecar push ids). Other internal failures keep the fixed 500.

Changes: server/router answers Postgres connection-loss classes 503 with Retry-After; TEST-M2-15's retryable half of the Postgres restart row.

Questions: `test-m2-15-postgres-restart-answer.md`.

### QD-760: What does a merge write for a document whose row and postings pass a shard's cap in a shard of their own?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §11 Encrypted versioned storage.*

Extractor 1's D6 skips a document (no entry, a tombstone where it was indexed before) when its key set would encode past KeySetMax or when it alone would not fit a shard, a test every device computes from the key set and row alone at extraction time, so no merge, push past DirectBytes or roll-up meets a document it cannot place. Such documents are not searchable, as documents past KeySetMax already are. The design agent amends DESIGN-DETAILS sections 1 and 11 with the exact test (the one-document shard's encoded length, or a bound of it every device computes alike) before the code changes.

Changes: D6 in DESIGN-DETAILS 11.2.3 and protocol/INDEX-FORMAT.md, before the index format freezes; the extractor's skip test and its tombstone; errIndexMergeUnplaceable stays as a closed guard that the rule makes unreachable; a short amendment to DESIGN-DETAILS sections 1 and 11 by the design agent, then a fix track in the lane holding SEARCH.

Questions: `search-m10-10-document-past-a-shard.md`.

### QD-761: What ends the fold's stop below a bridge body sealed to a generation that never forms?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §17 IP addresses, subnet routing, and port forwarding.*

A config writer that has held every generation the config repo's gkm head names for a set time (a settings field, 24 h by default) freezes a bridge body sealed above all of them as void (Refused, no such generation) and folds past it; a checker that lacks that generation too takes the head's rows unchecked, as now. The id level and the rows stay as they are, and no server sees anything new. The design agent amends DESIGN-DETAILS 12.2.3 with the exact rule (when the time starts, what a checker does, the fork argument) before FoldBridgeLedger changes.

Changes: DESIGN-DETAILS 12.2.3: the stop below an Unopened filing is bounded; a short amendment by the design agent; FoldBridgeLedger and BridgeLedgerFold.Stopped (BRIDGE-M4-23), with the wait as a settings field; then a fix track in the lane holding BRIDGE.

Questions: `bridge-m2-02-unopened-generation-stall.md`.

### QD-762: Where does the config repo's holders_shrunk_at live, now that its AclRepo row is the state's own and no rows hold it?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §8 Access control.*

TEAM's configSetShrunkAt adds the config repo's row to the rows at the first entry that shrinks its key holders, AclRepo{repo_id, kind: config, holders_shrunk_at: n}, sorted in with the rest, and advances it there afterwards like any repo's; configAdvanceShrinks judges the config beside the rows' repos, and QD-746's shrunk_repo_ids may name it. ACL's state keeps a config row the rows hold and synthesizes one only where the rows hold none, with holders_shrunk_at 0 there. This amends QD-719: no rows bytes change at the row's creation, and the rows change only when there is a shrink to record.

Changes: config_coverage.go: configSetShrunkAt and configAdvanceShrinks reach the config repo; acl_state.go's indexConfigRepo: the synthesized row's holders_shrunk_at is 0, not the state's position; the hand-built config rows leave sidecartest/gkmschedule/world.go, gkm_holders_test.go and gkmservice/reconciler_test.go.

Questions: `acl-config-repo-row-shrunk-at.md`.

### QD-763: Since gkm/dkey/<delegation_id> names no network, what tells QD-675's sweep which network's rows an object answers to?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §10 Group keys for evs: MLS and the GKM service.*

A forwarding Delegation's reader key object is gkm/dkey/<network_id>/<delegation_id>. The engine takes the network from the token at the upload and the read; gkm's reconciler lists one network's prefix at its pass now and then and deletes at once any object that no forwarding row in the state's rows and no tracked end names, which is QD-675's sweep. A network's shred or a hold finds its key objects by the prefix. The network id in the key is an opaque id (I-13), as a group's and a repo's are. This changes QD-442's path form for this family; nothing in production holds one.

Changes: GkmDelegationKeyPath (gkm_paths.go) and its callers in the root and gkmservice; testdata/gkm/wrap_paths.json; the reconciler's per-network sweep of gkm/dkey/<network_id>/ (QD-675's second part); sidecar/metadata_list.yml gkm-1's store line; §10.6's object table through design-records.

Questions: `core-owner-fixes-dkey-sweep-network.md`.

### QD-764: Where do rows get a route rule's via subjects when it names no `via`, which QD-004 makes the advertisers its BridgeRoutes name, and how does a gate tell an exit rule's via subjects from its other targets?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §8 Access control.*

BridgeRows gains repeated BridgeRouteRow routes = 2 {bytes route_id = 1; bytes advertiser = 2; repeated bytes route_rule_ids = 3;}, written at the fold for every approved route in force and applied by every verifier in log order after a base, as the egress mode is. AclState adds each advertiser to the via subjects of the no-via route rules its row names, which builds QD-004's second half. AclRule gains repeated AclTarget via = 12, so a rule's via subjects no longer share targets with its dial destinations and an internet rule that names a via holds to it at every gate. The server sees the ids §17.8 already describes, with an api-7 line.

Changes: acl.proto and the bridge rows proto: BridgeRouteRow, BridgeRows.routes = 2, AclRule.via = 12, listed in protocol/design_unfenced_test.go's testFenceAdditions; the fold writing the routes rows, CompileAcl moving via subjects to via, AclState, MayRoute, AclEngine.AllowRoute, the contract gate's Reach, RouteRules and ExitRules; sidecar/metadata_list.yml api-7; BRIDGE-M4-16's subject rows for a no-via rule.

Questions: `acl-m2-17-no-via-route-advertisers.md`.

### QD-765: Where should evs write which statement a slot object belongs to: object metadata, a field of EvsSlotObject, or nowhere?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §11 Encrypted versioned storage.*

evs writes each slot object's creating statement as its origin (push id, statement hash prefix, ref, signer sidecar, base version, path epoch, mode: at most 190 B) in object metadata on slot/ objects, key origin, set by the create If-None-Match and returned to no client. Step 6 takes an existing object only under its own statement's origin, and evacuation deletes a dead record's slot only when the origin is that record's statement; an absent or unparseable origin means the object is no statement's, never taken and never deleted by evacuation. No format-1 message, route or client changes.

Changes: DESIGN-DETAILS section 14 stands as written (14.2.2, 14.8); §2.8 evs-5's sees and ttl, and §19.6's MinIO row (a slot/ object's origin beside QD-248's idx/ entry state): sidecar/metadata_list.yml with the list's version bump, in the fix track; DESIGN.md text by design-records from 14.8; evsservice: slot_origin.go (new), push_commit.go, resolve.go, check_objects.go, erase.go, evacuate_resolve.go, evacuate.go, settings.go (14.7's track 2).

Questions: `details-14-slot-origin.md`.

### QD-766: Should evacuation stop deleting dead records' slots now, as an interim fix, before the full slot fix is built?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §11 Encrypted versioned storage.*

Evacuation stops deleting the slots a dead batch record lists, as an interim that lands before the full slot fix: evacuate_resolve.go's dead branch queues no slot. It closes the honest retoken's loss (14.1 A) and the hostile re-listing (14.1 B) at the cost of leaked slot objects of at most 8 KiB each. The full fix (QD-765) turns the delete back on for a dead record's own slots one release after every process writes origins.

Changes: evsservice/evacuate_resolve.go: the dead branch queues no slot (DESIGN-DETAILS 14.2.8, 14.7's track 1); FS-8's slots clause reads 'and its slots stay' until the full fix; cases C and D of 14.1 stay open until the full fix.

Questions: `details-14-interim-first.md`.

### QD-767: Should evs hand a retoken the slot its refused statement created, or refuse it and have the push rebuilt?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §11 Encrypted versioned storage.*

A retoken that meets the slot its refused statement created takes it over: evs deletes the refused statement's object and the retoken creates its own, when the origin names a push on the same ref by the same signer in a lower path epoch that the head does not show committed, the bytes are equal and no hold applies. The DELETE names the object's LastModified, after evs waits until the object is past the settle age (SlotSettleAge, a settings field, 2 s by default). A CLOSURE is uploaded and charged once across a retoken. Any other statement's object is 409 SLOT_STALE.

Changes: DESIGN-DETAILS 14.2.4 stands as written; amendments 14-B (9.2.5's slot paragraph) and 14-C (9.3's K) apply; evsservice writeSlot: the takeover, the settle wait and the Resolve in the push route (14.7's track 2).

Questions: `details-14-retoken-takeover.md`.

### QD-768: Should 5h refuse a deposit whose version names a slot its own push does not introduce?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §11 Encrypted versioned storage.*

On a deposit ref, every slot a new version names is one its own push introduces; otherwise 5h refuses the push 409 SLOT_UNKNOWN, recorded, as an unknown slot is today. With step 6's origin rule, each slot a consumed deposit names was then created by that deposit's statement and by no other, so CONSUME's delete needs no check of its own.

Changes: evsservice/check_objects.go: 5h's deposit-ref condition (DESIGN-DETAILS 14.2.6, 14.7's track 2); §11.8's 5h and §11.12's deposits row text, by design-records from 14.8.

Questions: `details-14-deposit-cited-slots.md`.

