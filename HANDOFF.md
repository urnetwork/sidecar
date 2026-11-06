# Sidecar: design-to-implementation handoff

*2026-11-06. From the design team to the implementation team.*

This is where building the sidecar infrastructure starts. The design is finished. [DESIGN.md](DESIGN.md), about 21,300 lines, holds every decision, and this document maps it: what to read, what to build first, what must never break, and what is still open. Where the two disagree, DESIGN.md wins. Tell the owner, and fix whichever is wrong.

## Contents

1. [The short version](#1-the-short-version)
2. [The documents](#2-the-documents)
3. [The system on one page](#3-the-system-on-one-page)
4. [Rules that bind every change](#4-rules-that-bind-every-change)
5. [Repos, branches and code placement](#5-repos-branches-and-code-placement)
6. [Milestones, tracks and gates](#6-milestones-tracks-and-gates)
7. [M0 in detail](#7-m0-in-detail)
8. [Testing and verification](#8-testing-and-verification)
9. [Area guides](#9-area-guides)
10. [Open items, risks and evidence gates](#10-open-items-risks-and-evidence-gates)
11. [Changing the design during implementation](#11-changing-the-design-during-implementation)
12. [Vocabulary for day one](#12-vocabulary-for-day-one)

## 1. The short version

- **What we are building.** The sidecar infrastructure is the end-to-end encrypted substrate under two products: recURd, the private record of agent work, and burner email, a consumer product in the URnetwork apps. It has these parts:
  - the `github.com/urnetwork/sidecar` module: the `sidecar.Sidecar` core, its subprotocol over connect, the stdio MCP server, the `ur` CLI and the service engines;
  - the scaled services that the server repo hosts: evs, gkm, sockets, dns with its dns edges, certs, tlsedge, smtpedge and mxedge;
  - team management and access control in server;
  - `sdk/sidecar.go`;
  - default-off changes on connect;
  - build and deployment through sn, warp, config, vault, build, xops, mmm and the `minio` fork.

  See DESIGN.md's opening and [§1](DESIGN.md#1-context-goals-and-requirements).
- **The one rule.** "End to end encryption is a must. The storage, tls edge, mail must only see encrypted bytes and some small header values like sni and spam headers." A server component that would see plaintext content is a design error and is never offered as an option ([owner directive](DESIGN.md#owner-directive)).
- **State of the design.**
  - No question is open. [Appendix B](DESIGN.md#appendix-b-open-questions-register)'s 200 questions break down as:
    - 173 decided by the owner;
    - 11 closed by peer review;
    - 12 closed by the internal design review of 2026-11-03, which reviewers may reopen;
    - 4 withdrawn.
  - Owner decisions 1-196 settle the cross-cutting choices ([owner decisions by number](DESIGN.md#owner-decisions-by-number)).
  - The owner signed G0 on 2026-11-06 (owner decision 193), and M0-M10 build straight through on the `sidecar` branches (owner decision 194). Nothing is frozen. Each format's specification freezes at its milestone's entry review and its bytes at the exit review ([§23.8](DESIGN.md#238-review-gates)).
- **What to do first.** M0, "Foundations" ([§23.4](DESIGN.md#234-milestones); [section 7](#7-m0-in-detail) lists it in full):
  - open the `sidecar` branches;
  - bootstrap the sidecar repo and wire its consumers;
  - start the in-house MLS subset with its X-Wing KAT;
  - draft RECORD.md;
  - run §12's DNS census and renewal;
  - start `smtpproof`;
  - run the staged auth fix's first stage, log-only, in production;
  - run G0's re-checks and density review beside the bootstrap (owner decision 193).
- **The critical path.** It runs through M2 ([§23.5](DESIGN.md#235-x15-two-tracks-and-staffing)):
  - the MLS subset, owner decision 43's 2-4 engineer-months;
  - the 0x0010 interop artifact;
  - the production hosts' PM9A3 set, which M2's storage benchmark needs before M2's exit.

  Both tracks share M0-M2, so a slip there moves every later milestone's exit. The build itself goes on past M2 with formats unfrozen (owner decision 194).

## 2. The documents

| Document | What it is | When you need it |
|---|---|---|
| [DESIGN.md](DESIGN.md) | The design: 23 sections, appendices A-H and the owner's decisions | Always. It is generated; do not edit it by hand ([section 11](#11-changing-the-design-during-implementation)). |
| [design/source/](design/source/) | DESIGN.md's sources, the owner's full decision record, the conventions, and the build-and-validate scripts | Changing the design; reading why the owner decided something (`owner/DECISIONS.md`) |
| [DESIGN-REVIEW-RESPONSE.md](DESIGN-REVIEW-RESPONSE.md) | The review ledger: every finding from six peer reviews, what changed, and what reviewers re-check at which gate | Before each gate. Its §2.3, §6.6, §7.2, §7.3 and §8 are implementation inputs. |
| [DESIGN-REVIEW1.md](DESIGN-REVIEW1.md), [1b](DESIGN-REVIEW1b.md), [2](DESIGN-REVIEW2.md), [3](DESIGN-REVIEW3.md), [3b](DESIGN-REVIEW3b.md), [META](DESIGN-REVIEW-META.md) | The peer reviews themselves | Rarely; the ledger answers each item |
| [design/PLAN.md](design/PLAN.md) | The owner's starting plan | Its statements are requirements unless a D- or Q- item departs from them. [Appendix F](DESIGN.md#appendix-f-planmd-traceability) traces every line. |
| [design/design-research/](design/design-research/) | Research fact sheets, cited in DESIGN.md as `[R:key]` | Checking a fact about existing code or an external system |
| [design/](design/) | Business documents: pitch5, product.md, market notes, mocks and reports | Product context; the source keys P5, PM, MK2, MM, RA, TM and REC in DESIGN.md point here |
| [FEEDBACK-SYSTEM.md](FEEDBACK-SYSTEM.md) | The recURd feedback system spec | Out of scope for this design (DESIGN.md's opening) |
| `cli/UI.md` | A sketch of the `ur` command set (source key UI). It sits at `urnetwork/cli/UI.md`, outside any git repo. | Designing CLI output. It still lacks `ur devices` ([section 10](#10-open-items-risks-and-evidence-gates)). |

**Reading DESIGN.md.**
- Every section follows one template: purpose and scope, requirements, what exists today, the design, alternatives, decisions proposed, open questions, departures from PLAN.md, interfaces, risks and phasing ([how to review](DESIGN.md#how-to-review)). To implement a section, read its design subsections and its interfaces; its phasing says what lands when.
- Ids are stable, so search for them.

| Id | Meaning |
|---|---|
| `R-CODE-n` | A requirement |
| `D-CODE-n` | A decision |
| `Q-CODE-n` | A question, with its answer |
| `I-1`-`I-20` | Security invariants ([§2.9](DESIGN.md#29-security-invariants)) |
| `I-EVS-1`-`I-EVS-17` | Storage invariants |
| `C1`-`C19` | Connect changes |
| `FS-n` | Fault schedules |
| `FI-n` | The invariants fault schedules check |
| `M0`-`M10` | Milestones |
| `X1`-`X20` | Cross-cutting decisions |

  "Owner decision N" links to row N of [owner decisions by number](DESIGN.md#owner-decisions-by-number), and entry N of `design/source/owner/DECISIONS.md` gives its full question, answer, cost and rejected options.
- Code is cited as `repo/path/file.go:LINE`, relative to the urnetwork checkout. Each section's "What exists today" subsection lists the code it builds on.

## 3. The system on one page

**Who is trusted with what** ([§2.4](DESIGN.md#24-assets-and-boundaries), [§2.5](DESIGN.md#25-server-visibility-matrix)). The adversary is a malicious server, possibly a compelled one (D-TRUST-1). Servers store, order and deliver ciphertext and signed statements, and the only statements they originate are denials (I-4). There are three trust boundaries:

- **TB1, the device.** It holds the daemon's keys and the plaintext. The harness and its agents run as the same OS user, and a cloud sandbox's operator is inside this boundary.
- **TB2, members.** They are trusted with what they are granted. One admin can admit a device or member, but changing the authority takes k of n. Nobody reads an owner-bound repo without the owner's consent, except the visible audit member a Team may opt into (owner decisions 63, 110, 126; I-4).
- **TB3, servers.** They are untrusted for both content and authority.

Where encryption ends depends on the service. For connect, tlsedge and certs it ends at the listening sidecar. For smtpedge and mxedge it ends at the destination MX or the receiving device. The exception is mxedge's `rpt.bringyour.com` report listener (mx-4). For evs and gkm it ends on readers' devices. api, sockets and dns carry no content.

**On the device** ([§3.4](DESIGN.md#34-component-map), [§3.6](DESIGN.md#36-runtime-topologies)):

- `ur daemon` runs one `Sidecar` per network, with its evs, gkm, sockets, mail, tls, bridge, mcp and search parts. It keeps the network's config repo in evs.
- A harness talks to `ur mcp` over stdio, and `ur mcp` relays to the daemon over a peer-uid Unix socket.
- Apps embed `sdk.Sidecar`. Network processes hold the keyless device role.
- The extension runs `sidecar.wasm` as a web worker once its own Worker lands (Later). Until then it reaches `ur daemon` by native messaging (M8), and ur.io pages run `sidecar.wasm` read-only (M4).
- Indexers are always-on `ur daemon`s (desktop, NAS or VPS), or Android with the VPN on for mail only, listed in the config repo's `IndexerSet` (owner decision 150).

**On the servers** ([§3.8](DESIGN.md#38-service-summary), [§19](DESIGN.md#19-server-services-deployment-data-stores-operations)):

- api, sockets, evs and gkm run on the lb hosts. evs and gkm hold no state of their own: everything durable is a MinIO object.
  - Metadata lives on NVMe metadata clusters. `place/<repo_id>` fixes each repo's cluster when the repo is created.
  - Segments live on an HDD cluster.
- tlsedge gets port 443's names under `<root>` and active custom hosts through the lb's SNI split, which leaves platform names on the http servers, and gets ports 8443, 8883 and 5671 unsplit. It routes by SNI without terminating TLS. mxedge takes inbound port 25. smtpedge sends on port 25 from the lb addresses.
- dns runs on the dns edge hosts. taskworker runs certs, the push sender and gkm's reconciler. connect's residents push hints.
- Postgres holds no file-storage state. Redis holds only soft state that can be rebuilt (owner decisions 2, 136).

**Six planes** (D-ARCH-2): control, push, peer data, IP data, bulk storage and public edges. Peer data is the sidecar subprotocol, id 21842, over connect. A new carrier needs an owner decision.

**The flows.** [§3.7](DESIGN.md#37-end-to-end-flows) walks thirteen flows end to end, and each step names the section that owns its mechanism. They double as §22.7's test scenarios S1-S13 (D-ARCH-3).

| Flow | What happens |
|---|---|
| F1 Enroll a sidecar | <ol><li>The invite carries the genesis anchor.</li><li>The device makes its own keys and calls `/network/enroll` and `/sidecar/bind`.</li><li>It connects to the network in Required mode, and a `SidecarAdmit` admits it.</li><li>It uploads KeyPackages and a ReaderKey.</li><li>It reads the config repo back to genesis before trusting any stream.</li></ol> |
| F2 Write and notify | <ol><li>git pushes to `ur mount`.</li><li>The daemon seals the push with path tokens, XChaCha20-Poly1305 and Padmé padding, then uploads it with `PUT seg/`.</li><li>evs batches the push and swaps the head with If-Match.</li><li>Hints and wakes go out.</li><li>The reader verifies the push and pins it.</li></ol> |
| F3 Add a reader | <ol><li>A `RepoGrant` is signed. In owner-bound repos only the owner's consented device shares, by `EvsShare`, and admins add only a Team's visible audit member.</li><li>A KeyPackage is claimed and the Add committed.</li><li>The new device processes the Welcome. Agents get a ReaderWrap instead.</li></ol> |
| F4 Publish HTTPS | <ol><li>`ur bridge public-tls` runs, with approval.</li><li>A certificate is ordered by DNS-01, and the listener registers.</li><li>The SNI split routes visitors to a Service-mode stream, and TLS ends in the listener.</li></ol> |
| F5 Send mail | <ol><li>A submission arrives, with recipient approval.</li><li>smtpedge checks the declared `SmtpPreamble` and splices the daemon's TLS to the destination MX.</li><li>It forwards records only after the preamble's proof verifies.</li></ol> |
| F6 Receive mail | <ol><li>mxedge refuses plaintext and routes by SNI `mx.<net>.<root>`.</li><li>The receiver terminates TLS and seals its authentication evidence.</li><li>It answers 250 only once the deposit is durable.</li></ol> |
| F7 Reach a subnet | <ol><li>`ur bridge expose` runs, with approval, and files a `BridgeRoute`.</li><li>A Required link carries a `WindowDelegation`.</li><li>An egress hook decides each flow.</li></ol> |
| F8 MCP recording | <ol><li>`ur mcp --agent` starts.</li><li>`ur hook` feeds sealed vault entries.</li><li>Outward tools stay pending until another device or a presence key signs, or, when neither exists, until the harness prompt approves.</li></ol> |
| F9 Remove a member | <ol><li>A signed revocation closes the gates, and tokens are refused.</li><li>The Remove commits and the keys rotate.</li><li>The first write to each file after that is a full checkpoint.</li></ol> |
| F10 Burner | <ol><li>The app makes a label locally.</li><li>A wildcard MX means no DNS record and no server state.</li><li>Burning the label is local.</li></ol> |
| F11 Search | <ol><li>Writers keep an encrypted trigram index beside the repo.</li><li>Index files sync by position.</li><li>Devices search locally, and the indexer, or else the first writer after a bucket expires, rolls the buckets up.</li></ol> |
| F12 Remote search | <ol><li>A phone sends fixed-size requests to its own network's indexer.</li><li>The indexer answers in fixed-size steps and fetches nothing.</li></ol> |
| F13 Directory | <ol><li>Runs announce who, what and where, and members request access.</li><li>A person signs the grant outside MCP.</li></ol> |

**What servers may see.** [§2.8](DESIGN.md#28-private-from-us)'s `metadata_list.yml` names every value any server sees, with its ttl. It is the product's promise, and it is published; [Appendix G](DESIGN.md#appendix-g-server-visible-metadata-list) points to it. Add a row in the same change that adds a server-visible column, Redis family, object family or proto field. §22.7's guard fails the build otherwise (I-18).

## 4. Rules that bind every change

These rules are hard. When a section cannot meet one, it raises a Q- item for the owner instead of working around it (D-TRUST-2; owner rule 8).

**The owner directive** ([full text](DESIGN.md#owner-directive)):

- **TLS edge (X1).** TLS terminates in the listening sidecar. tlsedge routes by SNI, never holds a user's TLS key, and has no termination mode.
- **Storage (X2).** evs and gkm see only encrypted bytes and small header values. Paths, file names, commit messages, author fields beyond the authenticated client id, and contents are all encrypted.
- **Outbound mail (X7).** TLS runs end to end from the sidecar's mail server through smtpedge to the destination MX. smtpedge sees only ciphertext plus a small declared preamble. There is no edge-terminated submission and no SES relay.
- **Inbound mail (X6).** TLS terminates on a device or a customer-run sidecar, never at a URnetwork edge, and there is no encrypt-on-receipt. The single exception is `rpt.bringyour.com`'s report and role-mail listener (D-SMTP-23; §15.4's mx-4).
- **Everything else.** Sidecar traffic over connect is Required, never Opportunistic or Off. gkm sees only encrypted MLS handshake data plus small headers. DNS reveals as little as it can.

**The owner rules** ([full text](DESIGN.md#owner-rules)):

1. New pieces, MLS included, live in the sidecar repo. server hosts the scaled services and takes team management and access control. sdk exposes the components.
2. sidecar depends on connect only. server and sdk import sidecar.
3. Nothing uses the deleted message repo or `connect/MESSAGEREVIEW.md`.
4. All work happens on a branch named `sidecar` in every repo it touches.
5. The layout follows PLAN.md's tree. Server-only engines go in child packages (owner decision 104).
6. The apps, console and extension UI are out of scope; only their seams are designed.
7. recURd is not tokenized, and it uses the URnetwork network for reach.
8. PLAN.md statements are requirements. A technical problem with one goes to the owner as a Q- item, with the PLAN position kept visible.

**The security invariants** ([§2.9](DESIGN.md#29-security-invariants)) bind every section:

| Invariant | Rule |
|---|---|
| I-1 | No server receives or derives keys to evs content or names, MLS secrets, or repo and path keys. "Stored in gkm" means wrapped. |
| I-2 | Content and keys reach servers only as ciphertext, in every mode. mx-4 is the one exception. |
| I-3 | Connections are `EncryptionModeRequired`, and the peer's identity binding is checked before its bytes are trusted. |
| I-4 | Every statement a client acts on is signed and checked against the config repo. Servers originate only denials. |
| I-5 | Receivers check every grant that exposes their data, sockets or LAN. |
| I-6 | No sidecar or agent credential administers the network or mints a login. This is the P0 auth fix. |
| I-7 | No credential enters an agent's MCP output, environment or logs. |
| I-8 | An outward action needs another approval-capable device or a presence key. Only when neither exists does the harness prompt count, and the evidence type is recorded. |
| I-9 | A run that read untrusted content, or lacks full hook coverage, loses send, forward and publish. It gets them back only when a person approves on another approval-capable device or with a presence key; a harness prompt counts only where its `requests` rule names harness. |
| I-10 | With an ACL document, only a rule opens loopback, LAN, link-local or overlay addresses. Without one, untagged sources keep the disclosed allow-all, minus the provider's own daemon listeners, and tagged ones get §8.5's implicit rules. |
| I-11 | Mail that URnetwork could read is labeled, message by message. |
| I-12 | Inline packet and frame paths never block on or query PostgreSQL, and they fail closed. |
| I-13 | URLs, names and logs carry opaque ids only. Client IPs are never stored or logged in the clear. |
| I-14 | A released name routes nothing to its new owner while the old owner's certificates, MX records, retries or sockets may still be honored. |
| I-15 | A removal revokes certificates, DKIM, TLSA and tokens, and starts a new key generation in each repo where the removed party held a key that no live Delegation still delivers. |
| I-16 | Heads, epochs, generations, the authorization log and config carry signed monotonic versions, and clients refuse lower ones. |
| I-17 | Off loopback, git over http, IMAP and submission serve only TLS, and local servers authenticate their callers. |
| I-18 | A metadata change updates §2.8 before release, or the build fails. |
| I-19 | No server receives a query or term, or learns a candidate or result beyond the documents a device opens. |
| I-20 | The directory holds only a run's who, what and where. |

**Storage and operations** (owner decisions 2, 90, 94, 136, 140, 145, 186):

- evs and gkm keep durable state only as objects in unversioned buckets: never in Postgres rows, never in durable Redis. Redis holds only soft state that can be rebuilt.
- Key slots and wraps are never backed up. There is one site and no off-site copy of the file clusters (owner decision 94).
- The metadata tier grows by whole clusters, never by MinIO pools. `place/<repo_id>` is written once, when the repo is created.
- The PM9A3 metadata set is a hard budget for all work except P0: at most 0.8 DWPD and 50% of rated IOPS. M2's benchmark gate is 43 KiB written per push per drive (D-TEST-11). P0 work is never queued or refused (owner decisions 186, 190).
- No backup outlives a published ttl. Sidecar tables go to their own daily dump, kept 14 days, and sidecar Redis families stay out of the rdb bundles (D-TRUST-7).
- Holds pause only server sweeps, GC and drop deletions, never a user's shredding (owner decisions 93, 133, 184).

**Shipping gates** (D-TRUST-3). No sidecar ships before the staged auth fix's first stage and the 7-day token expiry, and no desktop sidecar ships before stage 2. Until stage 2, enrollment refuses strict-expiry clients outside `preview_networks`.

**Code** ([§4.4](DESIGN.md#44-repo-tree-and-layering), [§4.7](DESIGN.md#47-module-dependencies-enforcement-consumption), [§4.9](DESIGN.md#49-generation-targets-versions-license-style); `make check` enforces these):

- **Layering.**
  - The root package imports only `protocol` and `protocol/bridge` from this repo.
  - `protocol/bridge` imports only std and protobuf.
  - No client package imports a `<svc>service`, and the root never imports `device/`.
- **Build legs.** `ios_extension` links neither the root nor `protocol`. `sidecar_http`, the browser Worker's leg, links no connect or gVisor package. There is no cgo except `keychain_darwin.go`.
- **Wire types.** The types the device role parses live only in `protocol/bridge`. Never declare a proto type twice: a duplicate panics at init. Run protoc from the repo root, and commit the `.pb.go` files.
- **Engines** never import server, so go-redis, minio-go and prometheus stay out of sidecar.
- **Test hooks.** From M0's `mls_*` on, call `testHookSecret` at every key creation, derivation and unwrap, and `testHookBarrier` at and around every linearization point. The privacy harness scans for every hooked key; fault schedules run on barriers and fake clocks, never sleeps. Both are empty without the `sidecar_testhooks` tag, and `make check` fails a release leg built with it ([§22.4](DESIGN.md#224-tiers-and-harness)).
- **Dependencies** are MIT, BSD-2/3-Clause, Apache-2.0, ISC or MPL-2.0 only. Shared module versions match connect, sdk and server.
- **connect changes** are generic, additive, off by default and wire-compatible. They merge to connect's `main` first.

**Process:**

- Commits carry no AI attribution. `commit-msg --scan main..sidecar` runs before each push and at each Gn-out ([§23.8](DESIGN.md#238-review-gates)).
- Secrets live only in vault.
- Tier limits come only through `config/all/pro.yml` and `model.Pro()`.
- A departure from PLAN.md needs a D- or Q- item. New scope needs a Q- item for the owner.

## 5. Repos, branches and code placement

**Repos** ([§4.3](DESIGN.md#43-what-exists-today), [§4.5](DESIGN.md#45-placement-and-the-sidecarserver-split), [§23.4](DESIGN.md#234-milestones)):

| Repo | Visibility | What it gets | `sidecar` branch from |
|---|---|---|---|
| sidecar | public (MPL-2.0) | The module: core, subprotocol, MCP, the `ur` CLI, the engines, protos and test support | M0 |
| connect | public | C1-C19's default-off changes ([§4.6](DESIGN.md#46-connect-changes-x9)) | M0 |
| server | public | Engine hosts (`server/cli/<svc>`), api routes, stores and migrations, taskworker, team management and access control, and the source-graph lock | M0 |
| sdk | public | `sdk/sidecar.go`, and four modules that require and replace sidecar | M0 |
| build | public | The `sidecar` submodule, the release step, and `warpctl build` and a rollout class for each service | M0 |
| sn | public (`urfoundation/sn`) | sidecar's require and replace, repeating server's | M0 |
| xops | private | D-OPS-18's sidecar dumps | M0 |
| mmm | internal | `install.sh` on ur.io | M0 |
| config | private | `config/<env>/sidecar.yml` (dark gates, `preview_networks`) and `pro.yml`'s `sidecar:` blocks | M0 |
| vault | private | Secrets | M0 |
| warp | public | W1-W11 ([§19.5](DESIGN.md#195-load-balancer-addresses-certificates)) | M0 |
| minio | public (AGPL-3.0), once the owner creates `urnetwork/minio` on GitHub | D-OPS-20's in-house MinIO build: a fork of upstream's final source, keeping MinIO's AGPL source in one public place (owner decision 195). No Go module imports it. | M0 |
| extension, apps | — | Nothing, unless the owner opts in | — |

At the handoff every one of these but the new minio fork was on `main`, with no `sidecar` branch. M0 opened each `sidecar` branch above on 2026-11-06, in the local checkouts: the owner directed one on every repo the work touches (owner decision 196). connect's checkout had one uncommitted local change, which is not part of this work.

**Branch policy** ([branch policy](DESIGN.md#branch-policy), [§4.8](DESIGN.md#48-branches-and-cross-repo-pinning), [§23.9](DESIGN.md#239-branches-merges-and-the-source-graph-lock)):

- **Merge, never rebase.** A rebase orphans pinned commits and skips the commit hook.
- **Weekly merges in.** `main` merges into every `sidecar` branch weekly and before each gate. The order is connect, sidecar, sdk, sn, server, then warp/config/vault/xops/mmm, then build. The source-graph lock is re-pinned each time.
- **Merges out at Gn-out.** At each milestone's exit review, every touched repo merges `sidecar` into `main` in the same order, connect's default-off changes first. This happens once the pinned set passes its checks and its migrations are additive and release-compatible.
- **Builds come from `main`.** Deploys, pilots and releases build from `main`, dark behind `config/<env>/sidecar.yml` (D-OPS-10).
- **Migrations wait.** Each migration group ([§19.7](DESIGN.md#197-postgresql-and-redis)) stays pending under the `sidecar_pending` build tag until its own Gn-out registers it, and never changes afterward (D-OPS-6; FS-54).
- **No private mirrors.** Every `sidecar` branch uses its repo's normal remote, and the sidecar repo is public as it is (owner decisions 117, 118).

**The sidecar module** ([§4.4](DESIGN.md#44-repo-tree-and-layering)):

```
github.com/urnetwork/sidecar
├── sidecar.go, settings.go, identity_*, keys_*, state_*, daemon_*, api_*   the core (§5)
├── envelope_*, rpc_*, stream_*, push_*, codec_*                            the subprotocol (§6)
├── host_*.go                                                               ServiceHost, which server supplies; Engine, which each engine implements and server hosts
├── acl_*, socket_*, mls_*, gkm_*, evs_*, dns_*, tls_*, smtp_*, mail_*,
│   bridge_*, record_*, directory_*, search_*, indexer_*                    each service's client side; MLS in mls_*
├── <svc>service/   pushservice socketsservice gkmservice evsservice dnsservice
│                   tlsedgeservice certsservice smtpedgeservice mxedgeservice   server-only engines
├── device/         the keyless device role; imports connect and protocol/bridge only
├── protocol/       config.proto acl.proto directory.proto search.proto
│   └── bridge/     signed.proto auth.proto bridge.proto; std and protobuf only
├── mcp/            the stdio MCP server
├── cli/            nested module: the ur binary, also run as git-remote-ur
├── smtpproof/      nested module: the outbound-mail preamble provers and verifier
├── sidecartest/    fakes and store suites
├── testdata/       vectors and goldens
└── mlsinterop/     nested module: differential MLS peers
```

**Toolchain and pins** ([§4.7](DESIGN.md#47-module-dependencies-enforcement-consumption), [§4.9](DESIGN.md#49-generation-targets-versions-license-style)):

- **Go and protobuf.** Go 1.27.3; protobuf and protoc-gen-go v1.36.11; built with `CGO_ENABLED=0 -trimpath`.
- **golang.org/x/text.** One version on every leg, at least v0.43.0. `make check` enforces this from M10.
- **Libraries.** go-sdk v1.7.0 for MCP. The test leg uses tmc/mls, mls-go v1.6.0, the mlswg interop client, and go-git as the git oracle.
- **Replaces and pins.** Replaces point connect, pion/sctp, glog and gvisor at sibling checkouts. Go does not inherit replaces, so server, sn and the four sdk modules repeat them. server's source-graph lock (`server/local/source-graph/lock.yml`) and build's submodules pin the same sidecar commits.

**Release** ([§4.9](DESIGN.md#49-generation-targets-versions-license-style), [§4.10](DESIGN.md#410-cli-distribution)):

- Versions are `yyyy.m.d-code`, built from `main`. The release rewrites the module path to `.../sidecar/v2026`.
- Packages are signed: `.pkg` for macOS; `.deb`, `.rpm` and `.pkg.tar.zst` for Linux; `.zip` for Windows.
- `install.sh` refuses to install unless an SSH-signed `SHA256SUMS` verifies.

## 6. Milestones, tracks and gates

Each milestone is a vertical slice with an entry review, an exit review and a dark deploy ([§23.4](DESIGN.md#234-milestones)).

- **v0** is what personal networks get: M0-M5 and M7-M9, with app hosts at M8.
- **v1** is M6, M10, and the Team items of M7-M9. M10 brings versionless objects and search to every network (owner decision 163).
- **Later** follows M9 and M10.

| Milestone | Builds | Exit shows |
|---|---|---|
| **M0** Foundations | <ul><li>G0</li><li>A draft of RECORD.md</li><li>§4's pre-code work</li><li>The staged auth fix's stage 1 and D-TEAM-14, log-only</li><li>The start of the MLS subset, with its X-Wing KAT</li><li>§12's domain renewal and census</li><li>The start of `smtpproof`</li></ul> | <ul><li>G0 passed</li><li>`make check` green</li><li>The lock entry on server@sidecar</li><li>P0 log-only in production</li><li>The sidecar dump running daily, its tables out of the main dump</li></ul> |
| **M1** Core, subprotocol | <ul><li>§5, §6 and §7 v0 up to the config repo, with the narrow `ur-cli`</li><li>§20's `sidecar:` blocks and counters</li><li>C3, C11, C12 and C15</li></ul> | <ul><li>Stage 1 and D-TEAM-14 enforced</li><li>Required RPC</li><li>Push resyncs after a resident restart</li><li>The envelope fuzzed</li><li>The daemon running on darwin, linux and windows, in `preview_networks` only</li></ul> |
| **M2** Storage | <ul><li>The config repo and key authority, with presence countersignatures, the leaf rule and `IndexerSet`</li><li>§8's projection and gates</li><li>HeadCheck</li><li>§10 v0, with agents on wraps</li><li>§11 v0a and v0b: git-mode tip CAS, placement and the write budget</li><li>Format 1, with format 2's numbers reserved</li><li>A staging cluster on the production hosts' PM9A3 set</li></ul> | <ul><li>The 0x0010 interop artifact</li><li>M2's fault schedules</li><li>Twenty agents</li><li>The storage benchmark's `nvme` gate: at twice year one's load, at most 43 KiB written per push per drive and at most 50% of rated IOPS</li><li>Servers get only §2.8's evs and gkm fields</li><li>The admission suite</li></ul> |
| **M3** Capture pilot | <ul><li>§16 v0, with `run_restore` and tainted-run evidence</li><li>`record.proto` frozen</li><li>The production file cluster</li><li>Device revocation, with `ur devices`</li><li>The out-of-hours rota</li></ul> | <ul><li>Hook conformance for Claude Code, Codex and Cursor</li><li>Restore writes only attributed paths</li><li>Re-seed drilled</li><li>The write budget live on production, with its monitoring</li><li>Dumps on schedule, and one restore drilled</li><li>Stage 2 live</li><li>The pilot running on personal networks</li></ul> |
| **M4** Reach; RS1 | <ul><li>Requested grants, suspension and the contract gate</li><li>§17 v0, with `ur tun`'s private names</li><li>C5, C6a, C8, C13, C14 and C16</li><li>§18's dark seam</li><li>ur.io/recurd's sign-in, downloads and page Worker</li><li>The escrow comparator, dark</li></ul> | <ul><li>Forwards, private IPs and model servers behind approved, expiring grants</li><li>Suspension within one epoch</li><li>A Claude Code cloud agent reaches a granted port</li><li>ur.io/recurd opens a vault record</li></ul> |
| **M5** Names, edge | <ul><li>Streams and Service edges (C9)</li><li>§9, §12, §13 and §21 v0, with `tls/`, the dns edge and edge login</li><li>§14's report host</li></ul> | <ul><li>The dns edge serves the user root</li><li>Platform names and company MX moved off ur.network</li><li>Passthrough publish</li><li>CT and zone watches alarm</li><li>A kill switch that acts in ≤ 5 s</li></ul> |
| **M6** Team; RS2 with M5 | v1 of §4-§13 and §16-§21, less format 2:<ul><li>SCIM and custom domains</li><li>Cross-network shares (C18)</li><li>Config wraps past a network's first 1,000 member devices</li><li>The team directory and the team console</li><li>`ur tun` on macOS and Windows</li><li>24/7 on-call</li></ul> | <ul><li>OIDC SSO</li><li>A removal blocks writes until its Remove commits</li><li>The team record</li><li>S13's schedules</li><li>A custom host turns ready only once every lb interface is current (FS-122)</li><li>Team billed</li></ul> |
| **M7** Inbound mail | <ul><li>§9's `smtp/`</li><li>§12's mail records, TLSA and the DS</li><li>§15's receive path</li><li>mxedge on port 25</li></ul> | <ul><li>SNI inbound reaches desktop, NAS and VPS mail indexers</li><li>DANE TLSA live</li><li>Plaintext senders refused</li><li>Validated labels</li><li>D-MAIL-9's census run</li></ul> |
| **M8** Burner; BS1, receive-only | <ul><li>§15's burners and app seams</li><li>App hosts, with sdk hosts and wake pushes</li><li>§13's app listeners</li><li>§17's Apple platforms</li><li>The directory's notice wakes on phones</li></ul> | <ul><li>Burner create and burn</li><li>Vault entries and one-time codes</li><li>The DeviceRemote mirror and receiver hosting API pass T4</li><li>Wake tokens in revision order (FS-120)</li><li>Release readiness, never a per-user gate</li></ul> |
| **M9** Outbound mail | <ul><li>§14 v0 on the shared lb addresses, with `ur/`, reverse zones and burner records</li><li>Sending, replies and forwarding</li><li>§21's mail ladder and breakers</li></ul> | <ul><li>D-SMTP-16's proof tests, DATA mode included (FS-123)</li><li>DANE-only MXs reached, and unauthenticated ones refused</li><li>Halt, ARF and RUA joins</li></ul> |
| **M10** Format 2, beside M6 | <ul><li>Versionless objects, the purge and history drops</li><li>git-lfs's versionless store</li><li>Format-1 migration</li><li>The search index in every eligible repo</li><li>Remote search and C19</li><li>`ur search`, `ur agents` and MCP search</li><li>The directory's cards</li></ul> | <ul><li>M10's schedules</li><li>D-TEST-13's drive-write gate</li><li>Index vectors byte-equal on every leg</li><li>A migrated repo's search equal to the oracle</li><li>Purge and drops in observe mode until production soaks pass</li></ul> |

**Later.** These follow M9 and M10:

- RS3: team legal holds, compliance mappings, and self-hosted and air-gapped installs.
- The extension's Worker and streams (C4).
- A designated-verifier prover.
- IPv6 subnet routes.
- The PSL listing.
- A move tool for placed repos.
- Embedding search on indexers.
- Delegating tasks to a worker's agent.

§7.4's stage 3 follows app adoption.

**Two tracks** ([§23.5](DESIGN.md#235-x15-two-tracks-and-staffing)):

- **Track A (recURd)** builds M0-M4 and M6.
- **Track B (mail and burner)** builds M5 and M7-M9, with four engineers by M2's exit.
  - One works from M0 on `smtpproof`'s BDAT and DATA proofs and on mail's lead times.
  - Then one each for edges and DNS, mail ingress and receivers, and app seams.
  - M5 is on track B because M7 needs its dns edge, DNSSEC soak, C9 and abuse intake.
- **M10 is track A's.** About three more engineers, hired from M3's entry, build format 2, the index and the search tools beside M6 from M4's exit. That is about 9-12 engineer-months, by inference.
- **Fallbacks.** If track B is not staffed by M2's exit, track A builds M5 before M6, and M7-M9 follow M6. If M10's engineers are not there by M4's exit, M10 follows M6. Either way, the owner is told then.

**What blocks each gate** ([§23.6](DESIGN.md#236-decisions-that-block-each-milestone)). For every milestone, §23.6 lists two things: the design closures its entry review needs, and the fault schedules its exit review needs. Read your milestone's row before its Gn-in.

**External lead times** ([§23.7](DESIGN.md#237-external-lead-times)). Start these early:

| Item | Due | Start | Notes |
|---|---|---|---|
| Domains | their dates | M0 | ur.network expires 2027-07-02 and is renewed to 2036 |
| File-cluster hosts with their PM9A3 set | before M2's exit; the rest by M3 | M0 | 4 hosts, each with 2 × PM9A3 1.92 TB and 16 × 16 TB HDDs. The next metadata cluster is ordered when §19.9's triggers fire. |
| Let's Encrypt domain override | M5 | M0 | "a few weeks", untimed |
| dns edge: two new hosts | M5 | M0 | |
| Platform names and company MX off ur.network | M5 | M2 | before the NS switch |
| On-call and abuse readiness | M3, M5, then M6 | M2 | a two-person out-of-hours rota (owner decision 143); 24/7 review from M6 |
| Counsel | M5 | M3 | confirms owner decision 133's condition and each hold kind |
| DNSSEC | M7 | M5 | 30 clean days before the DS |
| HE TCP 25 egress, reverse delegation, feedback loops | M9's entry | M0 | lead time unknown, so ask first |
| App releases | M3, then M8 | M1 | |

**Review gates** ([§23.8](DESIGN.md#238-review-gates)):

- **G0:**
  - peer review of DESIGN.md;
  - the density rule: each item lives in its owning section and is cited elsewhere;
  - D-ARCH-4's assembly check;
  - §23.6's M0-M2 items settled;
  - RECORD.md reviewed, here or by M2's entry.

  No code is written before G0 (D-PHASE-2). The owner signed it on 2026-11-06 (owner decision 193); its re-checks, density review and RECORD.md draft run beside M0's bootstrap.
- **Gn-in:**
  - §23.6's design closure for the gate;
  - specifications freeze;
  - review of the changes since G0 and of §22's exit-test plan.
- **Gn-out:**
  - exit criteria shown, with §23.6's schedules passing;
  - formats freeze;
  - §22's privacy assertions pass;
  - §2.8's list is updated;
  - `commit-msg --scan main..sidecar` is clean;
  - the owner approves the deploy and merges.

No external review gates any milestone (owner decision 99).

**How the build moves past a gate** (owner decision 194). M0-M10 build straight through in dependency order on the `sidecar` branches, with no stop at a Gn-out. Each gate's local checks run and are reported, and anything needing hardware, production or people is listed open: M2's format-1 freeze on the PM9A3 benchmark, M0's and M1's stages in production, each Gn-out's approval to merge. This changes how the milestones are executed, not what freezes when: §23.8's freeze order still decides what may reach a production store. Formats stay unfrozen meanwhile, so a later hardware miss could force rework in later milestones.

**What freezes when** ([§23.8](DESIGN.md#238-review-gates)). A specification freezes at Gn-in and its bytes at Gn-out. Before a final freeze, only local, T3, canary and M2's staging cluster hold a format. The production file cluster holds data from M3; sidecar's Postgres tables reach production earlier, from MG0 at M0.

| Gate | Freezes |
|---|---|
| M2 | <ul><li>§7.9's records, including the presence countersignature fields</li><li>Format 1, with format 2's reserved numbers. Its bytes also wait for D-TEST-11's `nvme` gate.</li><li>Credential 0xF552</li><li>Suite 0x0010</li><li>D-KEYS-10's delivery wire</li></ul> |
| M3 | `record.proto`, including owner decision 142's tainted-run rule and CanonicalAction's reserved field 37 |
| M6 | <ul><li>The escrow order, at M6's entry</li><li>`directory.proto`'s announcement, request, decision and notice messages</li></ul> |
| M9 | `smtpproof/SPEC.md` |
| M10 | <ul><li>Format 2, with the DROP payload</li><li>`directory.proto`'s cards</li><li>`search.proto`</li></ul> |

**Releases** ([§23.8](DESIGN.md#238-review-gates)):

- RS1's copy discloses I-10's allow-all for networks with no policy (owner decision 120).
- "End-to-end encrypted" copy waits only for three things: D-TRUST-4's document, §21.11's canary, and §2.18's disclosure that the cryptography is unaudited.
- BS1 waits for the census call and M8's mail-indexer readiness, never for a user's indexer.

**Risks to watch** ([§23.15](DESIGN.md#2315-risks)):

- **The MLS subset slips, or the unaudited MLS ships a flaw** (medium likelihood, critical impact). Mitigation: start in M0, and the interop artifact gates M2.
- **Hardware is late** (medium, high). Mitigation: order it in M0.
- **Year two's HDD PUTs fill the 50% line** (high by the model, high). Mitigation: the `hdd` run and its trigger.
- **Track B is unstaffed** (medium, high). Mitigation: the fallback above.
- **The BDAT or DATA proof misses D-SMTP-16** (high, high). Mitigation: BS1 launches receive-only.
- **Senders without SNI, and iOS-only users who miss codes** (high, high). Mitigation: the census, indexer paths and the `foreground-only` copy.
- **A purge, drop or migration destroys content** (low, critical). Mitigation: soaks and the FS rows.

## 7. M0 in detail

Both tracks share M0. Its scope ([§23.4](DESIGN.md#234-milestones)):

- G0;
- a draft of RECORD.md;
- §4's pre-code work;
- §7.4's stage 1 and D-TEAM-14, log-only;
- the start of §10.4's MLS subset, with its X-Wing KAT;
- §12's domain renewal and census;
- the start of `smtpproof`.

M0's exit needs G0 passed, `make check` green, the lock entry on server@sidecar, P0 log-only in production, and the sidecar dump running daily from MG0's Gn-out, with its tables excluded from the main dump (D-OPS-18). The items that need production stay listed open while the build moves on (owner decision 194). Its entry review needs §23.6's closures: the dump design, Q-TEST-1 and Q-TEST-2.

**1. G0 is signed.** No code is written before G0 (D-PHASE-2), and the owner signed it on 2026-11-06 (owner decision 193). The re-checks, the density review and the RECORD.md draft run beside M0's bootstrap, and their findings return as Q- items, so a finding could change something already built. G0's checklist at signing:

| G0 requires | State |
|---|---|
| Peer review of DESIGN.md | Done: five reviews and a final meta review, each item answered in [the ledger](DESIGN-REVIEW-RESPONSE.md). The meta review also covered the v1 additions. |
| A reviewer's re-check of the 21 fixed items the ledger places at G0 | Running beside M0's bootstrap. The list is in the ledger's §6.1, §6.2 and §7 (indexed by §4.6's By column); CC-02, a §7.3 entry, is among them ([section 10](#10-open-items-risks-and-evidence-gates)). |
| The density rule | A reviewer's judgment; no tool checks it. The review runs beside M0's bootstrap. |
| D-ARCH-4's assembly check | Passes: `design/source/build.sh`, 2026-11-06, with owner decisions 192-196. |
| §23.6's M0-M2 items settled | No question is open. |
| RECORD.md reviewed | Its draft runs beside M0's bootstrap. It is an M0 deliverable, reviewed by M2's entry. |

**2. Open the branches.** Create `sidecar` from `main` in sidecar, connect, server, sdk, build, sn, xops, warp, config, mmm and vault, all at M0 (owner decision 196). sn repeats server's sidecar replace, xops holds D-OPS-18's dumps, and warp takes W5 at M0 and W2 and W8 by M4 ([§19.11](DESIGN.md#1911-environments-gates-rollout)). The `minio` fork, a sibling checkout, cuts its `sidecar` from upstream's final source; the owner creates the GitHub repo before any push (owner decision 195).

**3. Bootstrap the sidecar repo** ([§4.9](DESIGN.md#49-generation-targets-versions-license-style), [§4.18](DESIGN.md#418-phasing)):

- The first commit on `sidecar` is the full MPL-2.0 text.
- Copy `.githooks/commit-msg` byte for byte into sidecar, config, vault and minio before their first `sidecar` commit. Its source is `connect/.githooks/commit-msg`, which the other touched repos already share.
- Install the hook once in every clone, as its header says: `git config core.hooksPath .githooks`, or copy it into the clone's hooks folder when the clone keeps other hooks. Copying the file into the repo does not install it, and a secret or AI-attributed message pushed to a public branch stays served by hash ([§4.17](DESIGN.md#417-risks)).
- Add CODESTYLE.md, the root's and `cli/`'s go.mod, `dependencies.yml` and `make check`.

**4. Wire the consumers** ([§4.7](DESIGN.md#47-module-dependencies-enforcement-consumption), [§4.8](DESIGN.md#48-branches-and-cross-repo-pinning)):

- Require and replace sidecar in server (plus `smtpproof`), in sn and in the four sdk modules.
- Add the pinned entry to server's source-graph lock, and `./cli/<svc>` to its service compile test.
- Add the `sidecar` submodule to build.
- Add the `run.sh` release step, after connect's and before sdk's, with its fixture.

`make check` must be green before the first consumer pins.

**5. Start the critical path** ([§10.4](DESIGN.md#104-implementation-ciphersuite-credentials), [§23.5](DESIGN.md#235-x15-two-tracks-and-staffing)):

- Build the in-house MLS subset in the root's `mls_*` files (owner decision 43) for suite 0x0010, which is X-Wing with Ed25519 (owner decision 44), and start its X-Wing KAT.
- Let `mls_*` run suite 0x0001 in tests too: no 0x0010 vectors exist, so the mlswg vectors and mls-go's differential runs use 0x0001, and tmc/mls's 0x004F stands in for 0x0010. The KAT runs the X-Wing draft's vectors against Go's `crypto/hpke` `MLKEM768X25519()`; OpenMLS's 0x004D, once it matches, is the second peer for any required step tmc/mls lacks ([§10.4](DESIGN.md#104-implementation-ciphersuite-credentials)).
- §7.9, §11 and gkm build in parallel against a fake of the subset.

**6. Run the staged auth fix log-only** ([§7.4](DESIGN.md#74-p0-a-client-token-never-administers); D-PHASE-3). Stage 1 and D-TEAM-14 reach production log-only at M0's Gn-out, in migration group MG0. Their 14 log-only days overlap M1, and M1 enforces them. MG0 holds `network_client_owner` and the altered `account_api_key` and `auth_code` ([§19.7](DESIGN.md#197-postgresql-and-redis)); once registered it never changes. Stage 1 also carries §7.4's auth-code fix: `auth_code` gains `api_key_id`, `/auth/code-login` refuses a code whose key is removed, and removing a key revokes the network token it minted. The 14 days watch `urnetwork_auth_child_admin_calls_total`: no shipped client sends a child token there.

**7. Start the long poles.**

- Begin `smtpproof`'s BDAT and DATA provers (owner decision 125).
- Ask HE about TCP 25 egress; its lead time is unknown.
- Renew the domains and run §12's census.
- Order the file-cluster hosts with their PM9A3 set, due before M2's exit, and the two dns edge hosts.
- Order to [§23.7](DESIGN.md#237-external-lead-times)'s spec: each host takes 2 × PM9A3 1.92 TB M.2 22110 (MZ1L21T9HCLS), dedicated to MinIO, plus separate boot media, 2 × 25 GbE and free NVMe bays, which the second metadata cluster takes. Add 2-4 PM9A3 cold spares, no PM963, and the cold spare chassis with its drives (owner decisions 136-139).

**8. Set up the test ground** ([§22.4](DESIGN.md#224-tiers-and-harness)):

- `sidecartest` builds on connect's exported API, and T3 reruns each fake-backed scenario on server's exchange (Q-TEST-1).
- The local stack matches production: a 3-master Redis Cluster and erasure-coded MinIO, with a CROSSSLOT lint (Q-TEST-2).
- Use Redis 8.10.2 and MinIO built from the `minio` fork, whose base, the final upstream source, has PR #21653's conditional-write fix: the deployed edge-5 build lacks it and proceeds when an If-Match read loses quorum ([§11.3](DESIGN.md#113-what-exists-today)). Locally, one 8-drive MinIO process at EC:4; in T3 and at the release gate, 4 × 2 drives at EC:4 and 4 × 4 at EC:8 ([§22.4](DESIGN.md#224-tiers-and-harness)).

**9. Draft RECORD.md** (owner decision 25). It holds recURd's record semantics beyond the X20 primitives. It is reviewed by M2's entry, and `record.proto` freezes at M3. Its scope ([Q-MCP-1](DESIGN.md#1614-open-questions)): record semantics, the v1 kind registry with each kind's search text, exports, the verifiable log, disclosure, model receipts (D-CTX-5) and cost. It may not change DESIGN.md's semantics ([§16.8](DESIGN.md#168-record-primitives-x20)): the logs' reader and writer matrix, per-entry key slots, the source and tainted labels, and approvals bound by `request_sha256` and `payload_sha256`.

**10. Start the sidecar dump.** xops runs D-OPS-18's daily dump of the sidecar tables, kept 14 days and excluded from the main dump. It also copies, in the same exported snapshot, the network, network_user (with its `network_user_auth_*` login rows) and network_client rows those tables name, each named network's admin user included, so a network, member or sidecar newer than the main dump keeps its id and rows. Pin planetoid's daily pull to 04:00 UTC, taking pg-sidecar first ([§19.6](DESIGN.md#196-the-file-cluster-x13)).

## 8. Testing and verification

[§22](DESIGN.md#22-testing-and-verification) owns verification, and testing carries more weight here than usual, for two reasons:

- **No cross-object transactions.** Storage is ordered only by single-object conditional writes. Every commit point, retry and cleanup must therefore be shown to hold under lost responses, crashes and stale processes (owner decision 2; D-TEST-10).
- **No external audit.** No audit gates a freeze or the "end-to-end encrypted" claim (owner decisions 99, 119).

**Tiers** ([§22.4](DESIGN.md#224-tiers-and-harness)):

| Tier | What it is | What it runs |
|---|---|---|
| T1 | The sidecar on every build leg | Unit and property tests, vectors, fuzz seeds |
| T2 | `sidecartest`: sidecars and engines in one process | Fake stores with an injected clock, store results and barriers |
| T3 | server hosting the engines on real stores | Store suites and the fault schedules |
| T4 | sdk | Bindings, wasm in Node, size and memory |
| T5 | A performance host and M2's PM9A3 staging cluster | §22.8's load runs and the storage benchmark |
| T6 | `tests/test-main.sh` | In `main`, dark, at each milestone |

**The fault program** ([§22.8](DESIGN.md#228-load-soak-failure-injection)):

- **Schedules.** FS-1 to FS-125 are deterministic schedules of actor steps, barriers, store faults and clock moves. They are checked against FI-1 to FI-30, and §23.6 names the gate each must pass.
- **Invariants.** FI-1 to FI-30 are closure, outcomes, commit-point authorization, one ladder, lifecycle, visibility, effects, attribution, git, witnesses, path integrity, recovery, accounting, the write budget, file-mode CAS, purge, versioning, index results, index erasure, roll-up, scope and taint, determinism, fetch privacy, remote search, directory authorship, request soundness, drop history, deliveries, copies and store settle.
- **Models.** TLC checks three TLA+ models at small bounds: `EvsCommit.tla` and `StoreSettle.tla` at M2, and `IndexRollup.tla` at M10.
- **Linearizability.** Porcupine checks T3's histories, per ref, against §11.8's commit rule.

**Crypto and formats:**

- §10.4's mapped vectors, the X-Wing KATs and the mlswg vectors.
- **The 0x0010 interop artifact, which gates M2.** `mls_*` and tmc/mls run one scripted lifecycle in both directions and must produce equal epoch authenticators and exporter outputs. `mlsinterop/` derives the key ladder in its own code.
- Vectors for §9's tokens and seals, §11's records, §8's definitions, the presence profiles, the index and `record.proto`, byte-equal on every leg.
- Fuzz targets whose seed corpora run as ordinary Go tests ([§22.6](DESIGN.md#226-fuzzing)).

**The privacy harness** ([§22.7](DESIGN.md#227-scenarios-privacy-revocation)):

- 32 random canary bytes are planted in every user field.
- The scan covers every engine handler but mx-4's listener input (§2.8's exception), every transfer frame, Postgres, Redis, every object, logs, metrics, edge records, DNS queries, push payloads, MCP results and a TLS-intercepting proxy. It reads raw and encoded forms and must find zero hits.
- A `sidecar_leaktest` build leaks into each of those places, and the scan must catch every leak.

**Suites.** Scenarios S1-S13 mirror §3.7's flows. Beside them run the admission, approval, restore and revocation suites (§22.7).

**Hot paths** ([§22.5](DESIGN.md#225-component-matrix-and-hot-path-gates)). The inline paths run with no Postgres and with op-counted Redis: the contract gate, Find, tlsedge, mxedge, the preamble, quota leases and the write budget. For example, the ACL gate must take under 1 µs with zero allocations.

**Load and benchmarks** ([§22.8](DESIGN.md#228-load-soak-failure-injection)):

- **Twenty agents.** Twenty agents push for an hour. The test is published.
- **The storage benchmark.** Its `nvme` run (D-TEST-11) runs at M2's exit on the staging PM9A3 set, and again on production before M3's pilot, measuring 4 KiB and 1 KiB XFS blocks. The gate holds on 1 KiB blocks, or on 4 KiB only if format 2's projected mix also fits there. At 2× year one's mix, with the write budget refilled at 0.8 DWPD, it must show:
  - no push refused;
  - at most 43 KiB per push per drive;
  - at most 50% of rated IOPS;
  - no `FOLD_BEHIND`;
  - every batch under 26 h.

  Its measured costs become §11.13's price table.

**Platform budgets** ([§22.9](DESIGN.md#229-conformance-and-platform-budgets)):

- `make size` keeps the iOS extension's device role within 1 MiB.
- The page Worker's wasm goal is 41,943,040 B.
- §18.4's memory budgets hold on iOS.

## 9. Area guides

Each guide covers one area: where its code goes, when it lands, what to read first, what to build first, what is easy to get wrong, what gates it, and what is still open. Each was written from the area's sections and checked against DESIGN.md's text; where the two disagree, DESIGN.md wins. Sections [4](#4-rules-that-bind-every-change) and [5](#5-repos-branches-and-code-placement) apply to every area, and the guides do not repeat them.

- [9.1 The sidecar core: identity, keys and local state](#91-the-sidecar-core-identity-keys-and-local-state)
- [9.2 The sidecar subprotocol](#92-the-sidecar-subprotocol)
- [9.3 Networks, teams, enrollment and the authorization log](#93-networks-teams-enrollment-and-the-authorization-log)
- [9.4 Access control](#94-access-control)
- [9.5 Socket listeners and the scheduler](#95-socket-listeners-and-the-scheduler)
- [9.6 Group keys: MLS and gkm](#96-group-keys-mls-and-gkm)
- [9.7 evs: format, push and commit, reads and git](#97-evs-format-push-and-commit-reads-and-git)
- [9.8 evs backend: the file clusters and the write governor](#98-evs-backend-the-file-clusters-and-the-write-governor)
- [9.9 Search: the encrypted index and remote search](#99-search-the-encrypted-index-and-remote-search)
- [9.10 DNS and the TLS edge](#910-dns-and-the-tls-edge)
- [9.11 Mail: outbound, inbound and burners](#911-mail-outbound-inbound-and-burners)
- [9.12 MCP, harnesses, the record and the team directory](#912-mcp-harnesses-the-record-and-the-team-directory)
- [9.13 Bridge: private IPs, subnet routes and port forwards](#913-bridge-private-ips-subnet-routes-and-port-forwards)
- [9.14 SDK, apps and the extension](#914-sdk-apps-and-the-extension)
- [9.15 Server services and operations](#915-server-services-and-operations)
- [9.16 Tiers, quotas, metering and billing](#916-tiers-quotas-metering-and-billing)
- [9.17 Abuse, safety and legal process](#917-abuse-safety-and-legal-process)

### 9.1 The sidecar core: identity, keys and local state

`sidecar.Sidecar`, one per network in a per-instance `ur daemon`, holds its own Required client, durable `sidecar_id` and identity key, handles enrollment, refresh, admission and revocation, gates outward actions, and seals a per-network keychain.

- **Code:** `sidecar` root package: `sidecar.go`, `settings.go`, `identity_`, `keys_`, `state_`, `daemon_`, `api_`; connect-using files carry `!sidecar_http` ([§4.4](DESIGN.md#44-repo-tree-and-layering)); `ur` in `cli/`. Server api: `POST /sidecar/bind`, `GET /sidecar/identity/<sidecar_id>`, never-reaped `sidecar_identity` and `sidecar_identity_binding` tables (migration ≥926).
- **Lands:** M1 daemon, enrollment, keychain, DPoP refresh; M2 admission, revocation, recovery code; M3 gate, own-device revocation; M4 page Worker; M6 several networks; M8 sdk hosts, pairing; M10 index cache ([§5.17](DESIGN.md#517-phasing)).
- **Read first:** [§5.4](DESIGN.md#54-sidecar-fields-settings-lifecycle-components) types, lifecycle; [§5.5](DESIGN.md#55-identity-x10) key roles; [§5.6](DESIGN.md#56-login-enrollment-admission-refresh-revocation) enrollment to revocation; [§5.9](DESIGN.md#59-local-state-keychain-os-key-stores-recovery) state, keychain; [§5.8](DESIGN.md#58-the-daemon-and-local-ipc) daemon, IPC.
- **Build first:** (1) every-leg root types, `DefaultSidecarSettings()`, net/http `SidecarApi` (M1); (2) U in `unlock.wrap`, per-network R_n, store states (M1); (3) enrollment, `POST /sidecar/bind`, DPoP refresh with `restore_required` (M1); (4) the daemon: `<state>/lock` flock, peer-uid check, JSON-RPC 2.0 (M1).
- **Easy to get wrong:**
  - Every-leg files use no connect type (convert via `connect.Id(id)`): connect links gVisor; a connect-only js/wasm main is 55.0 MB (D-CORE-1).
  - Only `Absent` with no recorded `sidecar_id` creates keys; `Locked` and `Failed` never create, overwrite or delete; a decoding or AEAD failure is `Failed`, never `Absent` (D-CORE-15).
  - A refused refresh means `Unenrolled`, identity kept; only a verified `SidecarRevoke` means `Revoked` (D-CORE-8).
  - One R_n per network: no recovery code opens another network's keys (D-CORE-14).
  - Persist the keychain only if the reply confirms `admin_refused` (D-CORE-7).
  - Mode grants nothing: admissions, `OwnerConfirm` and revoking another device need `/dev/tty` or app-UI confirmation, never MCP (D-CORE-13).
- **Gated by:**
  - [§22.5](DESIGN.md#225-component-matrix-and-hot-path-gates)'s §5 row at each component's milestone: wraps, store states, other uids refused, no secret in replies, fail-closed enrollment, one code opening no other network's keychain.
  - `make check` fails a `sidecar_http` leg linking connect or gVisor (from M1); M1-out: daemon on darwin, linux, windows, `preview_networks` only.
  - §22.7's admission suite (M2-out); FS-98, own-device revocation (M3-out; Team M6-out; app hosts M8-out).
- **Still open:** AUTHZ1 residuals: same-user processes can read the keychain; a copied token authenticates a transport until `exp` (Q-CORE-4 (c), Later). macOS falls back to the file-based login keychain or cgo if the bundle or purego fails §22.5 (§5.11).

### 9.2 The sidecar subprotocol

How sidecars talk over connect (subprotocol id 21842): chunked envelopes, peer RPC, streams, server hint push, Hello's identity check, HeadCheck witnessing and typed `Signed`.

- **Code:** sidecar root `envelope_`, `rpc_`, `stream_`, `push_`, `codec_` files; `sidecar/protocol`; `Signed` in `protocol/bridge`; server-only `sidecar/pushservice`, hosted by server/connect residents (`EnableSidecarPush`), api (long-poll) and taskworker (wakes).
- **Lands:** M1 envelope, Hello, RPC, push (C3, C12, C15); M2 Hello's admission check, HeadCheck, wire freeze; M4 control contracts, C13; M5 streams, edges (C9); M6 shares (C18); M8 wakes; M10 SEARCH, C19.
- **Read first:** [§6.5](DESIGN.md#65-envelope-size-budget-chunking) (envelope, chunking); [§6.4](DESIGN.md#64-id-allocation-versioning-negotiation-peer-identity) (Hello, identity check, HeadCheck); [§6.6](DESIGN.md#66-requestresponse-rpc) (RPC, settings); [§6.8](DESIGN.md#68-server-push-x8) (push, long-poll); [§6.11](DESIGN.md#611-message-catalog-index-and-codec-conventions) (registries).
- **Build first:**
  1. M1: protos; the envelope codec with TOO_LARGE past 4,080 B, 4,016 B chunks, a final-chunk SHA-256.
  2. M1: Hello's identity check (first-use pin per `sidecar_id`, EX6), then `Call`/`Handle`.
  3. M1: the `{scp_<C>}` hint script, `SidecarPublisher` and `GET /sidecar/sync/poll`.
  4. M2: HeadCheck with `proven`/`unverified` relays, alarm and stop.
- **Easy to get wrong:**
  - No stream or non-Hello RPC until the binding verifies, `client_public_key` equals C15's session key and `identity_public_key` matches the pin (D-PROTO-13).
  - Push only from `source.IsControlSource()` on h1, h3, h3dns or h3dnspump, since P2P can forge ControlId; nothing else from ControlId (D-PROTO-8).
  - INCR triggers hints (HSET and XADD emit nothing in production); Redis versions are decimal strings, never Lua numbers; a partial `PushReset` applies nothing (D-PROTO-12, D-PROTO-20).
  - Calls: 15 s default, 55 s cap; retry only immediate send refusals, keeping `request_id`; responses over 16 KiB go uncached: retries get ALREADY_EXISTS (D-PROTO-3).
  - Never refresh a pin not reconciled, nor count witnesses while holding an UNVERIFIED pin; rotations, Removes and revocations never stop (D-PROTO-17, owner decision 129).
- **Gated by:**
  - §22.5's §6 row: chunk limits, idempotency, zero rule, `oneof` lint, nothing before a verified Hello, p2p ControlId push dropped, partial reset, receive allocs.
  - M1 exit: Required RPC after the identity check; push resyncs after resident restarts; envelope fuzzing (§22.6).
  - FS-17 (M2-out), FS-21 (M4-out; Team at M6-out): forks, relays, control contracts (FI-10).
  - FS-125 (FI-24; M10-out, app hosts at M8-out): C19's windows.
- **Still open:** streams revisited if TLS-edge p99 shared-sequence stalls exceed 500 ms (D-PROTO-4); pooled codec only if §22 measures it worthwhile (D-PROTO-11); §2.8's bound fails across a split (D-PROTO-14).

### 9.3 Networks, teams, enrollment and the authorization log

Who administers a network and which devices it admits: the P0 client-token fix, enrollment, scoped tokens, and each network's signed `config` repo and authorization log.

- **Code:** server `api` (log sequencer, `rev/` writer, sole `{acl_<networkId>}e` writer; tables, migrations 926+), `server/api/route_authz.go`, `server/oauth` (exchange, edge login), `taskworker` (reaper); sidecar `protocol/config.proto`, `protocol/bridge/auth.proto`, the verifier; `sdk/sidecar.go` (DPoP signer).
- **Lands:** M0 stage 1 log-only; M1 enforced, enrollment, exchange, `rev/`; M2 config repo, log; M3 stage 2; M5 edge login; M6 Team; M10 `VersioningRules`, `search`.
- **Read first:**
  1. [§7.4](DESIGN.md#74-p0-a-client-token-never-administers): allowlist, `strict_exp`, DPoP proof.
  2. [§7.8](DESIGN.md#78-credentials-and-scoped-tokens): enrollment, `#<bundle>`, exchange, `rev/`.
  3. [§7.9](DESIGN.md#79-the-config-repo-customer-held-key-authority-x3), whole: records, log, authority, recovery.
  4. [§7.10](DESIGN.md#710-removal-and-consistency-with-mls-10): removal end to end.
- **Build first:**
  1. `model.ClientRefusesAdmin` in `refuseClientAdmin`, the allowlist, 7-day `exp`, log-only 14 days (M0).
  2. Enforce, installing `Api.SetDpopSigner` before D-CORE-8's refresher goes off; enrollment; the exchange and `rev/`, which block evs (M1).
  3. `auth.proto`, `config.proto`, api's If-None-Match sequencer over `proj/<network_id>/<n>/_`, the verifier, against a fake of §10.4's subset (M2).
- **Easy to get wrong:**
  - Off-allowlist `strict_exp` calls get 403, so the sdk does not sign out; a lookup error refuses admin (D-TEAM-1).
  - The `#<bundle>` is never sent, logged or passed to MCP; revoking its auth key at api leaves copies admitting (D-TEAM-22, D-TEAM-31).
  - api appends: on 412, re-verify and try the next position; on a timeout, GET the position tried. No base lowers `config_version` or `folded_through` (D-TEAM-19).
  - k of n counts distinct members, never targets or read_only devices; recovery-signed statements wait for an ApiTick 72 h after the newest recovery signature, unvetoed (D-TEAM-21).
  - A signer with a live presence key must countersign presence-row statements; a compromise revocation is refused if its parked set holds one of its signers (D-TEAM-32, D-TEAM-26).
- **Gated by:**
  - M1-out: stage 1 and D-TEAM-14 enforced; `TestSidecarTokenRoutes`, [§22.5](DESIGN.md#225-component-matrix-and-hot-path-gates)'s §7 row.
  - M2-out: [§22.7](DESIGN.md#227-scenarios-privacy-revocation)'s admission suite; FS-14, FS-16, FS-18, FS-62, FS-102, FS-124's M2 cases; records freeze ([§23.8](DESIGN.md#238-review-gates)).
  - Every `test.sh`: typed-`Signed` and config-delta fuzz seeds ([§22.6](DESIGN.md#226-fuzzing)).
  - M3-out: FS-41 (site loss). M6-out: 133 `admin_user_id` reads classified, OIDC SSO.
- **Still open:** accepted ([§2.10](DESIGN.md#210-threats-and-mitigations)): a recovery code reads its wraps at once until a compromise rebind (Q-TEAM-11); k = 1 when n ≤ 2. Copied tokens authenticate connect transports up to 7 days (§7.4). Stage 3 waits until under 1% of active app clients send client credentials for 14 days, or `upgrade_required` enforces SDK `bc72b109`.

### 9.4 Access control

Decides who reaches whom and who reads each evs repo. Sidecars compile the signed HuJSON policy into id-only `AclRows` and evaluate locally; server gates see only rows (D-ACL-15).

- **Code:** sidecar root `acl_*.go`, `protocol/acl.proto`; api tables, `/acl/` routes (§8.17); gates in `api`/`connect` (`CreateContract`), `sockets`, `evs`, `gkm`, `tlsedge`, `certs`, `dns`, `smtpedge`, `mxedge`.
- **Lands:** M2 rows, grant chains, local evaluation, evs/gkm gates, consent; M4 requested grants, `Suspend`, contract gate; M6 Team, shares; M10 `RepoVersioning`'s lock (§8.19).
- **Read first:**
  1. [§8.4](DESIGN.md#84-model): subjects, selectors.
  2. [§8.5](DESIGN.md#85-policy-document-and-worked-examples): kind defaults, consent, implicit document.
  3. [§8.6](DESIGN.md#86-evaluation-semantics): `allowed`, ephemeral ceiling.
  4. [§8.8](DESIGN.md#88-the-policy-in-the-config-repo-rows-grant-chains-saving): `AclRows`, grant chains, validation.
  5. [§8.12](DESIGN.md#812-acl-and-evs-readers): readers, seats, wraps.
- **Build first:**
  1. M2: `acl.proto` with D-PHASE-9's reservations: `autogroup:dst-owner`, `EvsShare.expires`, `RepoVersioning`'s lock.
  2. M2: `CompileAcl` (kind defaults first; the implicit document when `has_document` is false), `ur acl test`, lock- and allocation-free `AclEngine`.
  3. M2: evs/gkm current-reader gates, cached per (network, n), reloaded on `INCR {acl_<networkId>}v` ([§8.9](DESIGN.md#89-distribution-local-evaluation-and-gate-caches)).
  4. M4: `GrantActivate`, `Suspend`, `CreateContract`'s gate ([§8.10](DESIGN.md#810-enforcement-points)).
- **Easy to get wrong:**
  - Kind defaults compile from the binary first; `*` never matches their kinds; documents never change `directory`'s (D-ACL-24).
  - `autogroup:untagged` excludes sidecars (D-ACL-20); ephemeral sidecars get only §8.6's evs ceiling (D-ACL-19).
  - Owner-bound repos: admins only revoke or add the audit reader (owner decision 126); readers honor `EvsShare.expires` from M2.
  - Deposit implies no read; evs and gkm honor `r`, `rw`, `admin` only for current readers and writers, not a token's 15 minutes (D-ACL-21).
  - Companion contracts check `reach(b,a)` (D-ACL-4); networks without a head row cost one map miss (R-ACL-8).
- **Gated by:**
  - §22.5: compiled = reference, fixed vectors, gate < 1 us, 0 allocs, `DenyPostgresForTest`.
  - Fuzz (every `test.sh`): HuJSON compiler, typed `Signed`.
  - M2-out: FS-14, FS-19's config read, FS-62, §22.7's admission suite.
  - M4-out: FS-19's grant runs, FS-21; M6-out: FS-85.
- **Still open:** no Q-ACL question. §8.5 leaves `github.com/tailscale/hujson` versus an in-repo parser to §4, unchosen (§4.7). Accepted: shares check only the other network's whole reader population (§8.11); reaped agents keep a live Delegation's key until it drops (§8.12).

### 9.5 Socket listeners and the scheduler

Clients lease `[<net>:]<name>` registrations; for each Find, the `sockets` service picks two listeners by weighted P2C and signs a single-use ticket for each, which the listener admits against its own config.

- **Code:** sidecar root `socket_*.go`; engine `socketsservice/`, hosted by `server/cli/sockets` on every lb host (D-SOCK-10); state only in Redis Cluster.
- **Lands:** M5 v0 (`tls/`, Go API, `ur socket`, `ur share`), after §6 streams, M2's projection and C9; M6 affinity, Team scope hosts; M7 `smtp/`; M9 `ur/` ([§9.17](DESIGN.md#917-phasing)).
- **Read first:**
  1. [§9.4](DESIGN.md#94-addresses-and-namespaces): names, token paths, seals.
  2. [§9.5](DESIGN.md#95-registration): paged 45 s leases.
  3. [§9.6](DESIGN.md#96-find-and-accept): Find, tickets, admission.
  4. [§9.7](DESIGN.md#97-the-scheduler): P2C, clamp.
  5. [§9.10](DESIGN.md#910-acl-quotas-abuse-identity-metrics): gates, bounds.
- **Build first:**
  1. M5: `ParseSocketAddress`, tokens and seals against fixed vectors (T1).
  2. M5: `SocketStore` on [§9.8](DESIGN.md#98-the-sockets-service)'s per-group hash tags (D-SOCK-7): registration pages, then Find as one script.
  3. M5: ticket signing, listener admission, dialer retry, then the Go API.
- **Easy to get wrong:**
  - Find order: bound, projection (before reading the group), spend, pick, sign; refusals sign nothing (D-SOCK-15); the service never contacts listeners (D-SOCK-4).
  - Clamp c = max(4, ⌊10% of `max_streams`⌋) bounds `est` only, never refusing or delaying a ticket (D-SOCK-5); nothing caps names, listeners or streams (owner decision 66).
  - Every ticket's `dialer_client_id` is the Required session's source, edge tickets included (D-SOCK-12); admission step 6 is the listener's own config evaluation (owner decision 6).
  - Plaintext names outside `tls/`, `smtp/`, `ur/` are refused (D-SOCK-13, owner decision 67).
  - A registration page is the whole set within `[key_start, key_end)`: absent entries unlisten (D-SOCK-3).
  - `ur share`: a crash never frees a Reserve; nothing serves at or past `expire_millis` (D-SOCK-16).
- **Gated by:**
  - §22.5's §9 row at M5 (§22.17): stale-load P2C oracle, vectors, replay, 3,000-name pages, Redis-loss rebuild, clamp; Find under `DenyPostgresForTest`.
  - §22.8 at M5: 100,000 listeners, Find p99 ≤ 50 ms server-side (proposed).
  - §22.4's CROSSSLOT lint.
- **Still open:** Nothing open.

### 9.6 Group keys: MLS and gkm

An in-house, pure-Go MLS subset (RFC 9420, suite 0x0010) gives each evs repo one group, whose epochs export a key-encryption key for repo-key generations RK_g. gkm, a stateless Delivery Service over metadata-cluster objects, orders commits and stores RK_g only wrapped.

- **Code:** sidecar root `mls_*`, `gkm_*` (`GkmClient`), `protocol/gkm.proto`, `gkmservice/`; test peers in nested `mlsinterop/`. Server: `server/cli/gkm` (D-OPS-2), reconciler in taskworker, limits in `config/all/pro.yml`. No tables; acks in Redis `{gka_<group_id>}`.
- **Lands:** M0 starts the subset; M2 §10 v0, agents on wraps; M6 v1 (config wraps past the first 1,000 member devices, the directory group, the audit reader); M10 the `index` purpose ([§23.4](DESIGN.md#234-milestones)).
- **Read first:** [§10.4](DESIGN.md#104-implementation-ciphersuite-credentials), subset and framing; [§10.5](DESIGN.md#105-the-key-hierarchy-what-one-session-key-stored-in-gkm-means), hierarchy, Rotate, KeyHolders; [§10.6](DESIGN.md#106-gkm-the-delivery-service-and-wrapped-key-store), objects, checks, scopes, gate; [§10.9](DESIGN.md#109-authorization-of-mls-operations), what members verify; [§10.7](DESIGN.md#107-flows), KF1-KF7.
- **Build first:**
  1. M0: `mls_*` with its X-Wing KAT; the subset is M2's critical path ([§23.5](DESIGN.md#235-x15-two-tracks-and-staffing)).
  2. M2 Gn-in: specify the MLS wire (0xF552, `GkmCommitHeader`, `GenRotate`, `ur_group`) and delivery wire (`ReaderKey`, `KeyDelivery`); no field removed after (D-KEYS-10).
  3. M2: `gkm_*` and `gkmservice` against a fake of the subset: Rotate, KeyHolders, gate predicate, KF1-KF7.
- **Easy to get wrong:**
  - Removal is a Remove commit plus a separate `gen/<g+1>` claim; MLS commits never raise the generation (D-KEYS-15).
  - Rotate stages every delivery before claiming; on 412, adopt the winner only if it covers what you rotate for, else take g+2 (D-KEYS-15).
  - gkm sees no proposal, so members verify every commit and wrap; wrapped writers never commit Add or Remove (owner decisions 59, 114, 144, 182).
  - A covered agent's reap is no shrink; its `Suspend` or non-reap revocation drops its Delegation's key (D-KEYS-16).
  - ReaderKey `not_after` ≤7 days after signing; replace at 6 days; keep private keys 30 days past it (D-KEYS-25).
  - KF1 writes first wraps before evs activates the repo (D-KEYS-18); retention never deletes the newest epoch (D-KEYS-20).
- **Gated by:**
  - [§22.10](DESIGN.md#2210-internal-review-gates)'s 0x0010 interop artifact, mlswg vectors, differential runs, fuzz targets, §10.6's sizes: M2 Gn-out (D-KEYS-10).
  - EvsCommit.tla and StoreSettle.tla passing TLC: M2 Gn-in and Gn-out.
  - FS-6, FS-15, FS-18, FS-20, FS-22 to FS-24, FS-62, FS-102 to FS-106: M2-out; FS-87: M6-out.
- **Still open:**
  - A required interop step tmc/mls lacks holds the freeze unless OpenMLS's 0x004D runs it both ways.
  - Q-KEYS-11: §19.9's epoch-retention size awaits §22.8's M2 benchmark.
  - Unaudited MLS, disclosed (D-KEYS-10); IANA renumbering migrates groups via GroupForm and the ladder (D-KEYS-12).

### 9.7 evs: format, push and commit, reads and git

evs stores each repo as ciphertext on the MinIO file cluster; its stateless server holds no key and never parses git. A ref moves only by an If-Match PUT of its `head/`; readers verify signed `EvsPush` chains; a local git tier serves stock git.

- **Code:** root `evs_*.go` (`EvsClient`, `EvsRepo`); `sidecar/evsservice`; `sidecar/protocol/evs.proto`; `server/cli/evs` at `evs.bringyour.com`; taskworker jobs; `connect/api/bringyour.yml` routes; `cli/`'s `ur`, also `git-remote-ur`.
- **Lands:** M1 routes (C11); M2 v0a (format 1) and v0b (git tier); M3 production cluster; M6 `directory` streams; M10 format 2.
- **Read first:** [§11.8](DESIGN.md#118-the-evs-service-objects-push-commit-reads) (push, outcomes, gate), [§11.6](DESIGN.md#116-format-keys-tokens-records-segments) (tokens, `evs.proto`), [§11.7](DESIGN.md#117-diffs-checkpoints-index-entries-reconstruction) (modes, folds, markers), [§11.9](DESIGN.md#119-head-read-api) (reader checks), [§11.11](DESIGN.md#1111-the-local-tier) (git tier).
- **Build first:**
  1. M2 Gn-in: `evs.proto` (format 2's numbers reserved), `EvsCommit.tla`, `StoreSettle.tla`, FS rows on the fakes.
  2. M2, before v0a: `ServiceHost.Blobs` per cluster: If-Match puts, streamed put, ranged get, delete ([§4.4](DESIGN.md#44-repo-tree-and-layering)).
  3. M2 v0a: `evsservice`'s steps 4-8, batches, folds, placement; client push builder, verifying reads.
  4. M2 v0b: git server, committer hook, proc-receive journal, `git-remote-ur`.
- **Easy to get wrong:**
  - Immutable families count a 412 on equal bytes as success; each head write raises version or fence, so ETags never repeat (D-EVS-13).
  - No answer deletes anything (I-EVS-2); step 7 only within 5 s of step 4's reads; unsettled refusals are first recorded in the head (≤8, else 429) (D-EVS-23).
  - MinIO's DELETE ignores preconditions and a multi-pool PUT checks only the pool it picks ([§11.3](DESIGN.md#113-what-exists-today)): grow by whole clusters (owner decision 145); collect markers only on builds past FS-114 (owner decision 148).
  - Git-mode refs commit only on TIP, FORCE and PATH_EPOCH included, never by server merge; committer `<client_id>@ur.invalid` (owner decisions 81, 141; D-EVS-22).
  - Creations take max(b, m) + 1, so versions never restart (I-EVS-8); `idx/` is newest only with the window past a prior head's `folded_through` (D-EVS-31).
- **Gated by:**
  - M2 Gn-in ([§22.10](DESIGN.md#2210-internal-review-gates)): peer review of §11.5-§11.8 and RECORD.md; both models pass TLC.
  - M2 Gn-out: §22.5's §11 vectors; §22.6's fuzzing; FS-1 to FS-12, FS-57 to FS-63, FS-113, FS-114's head and marker cases; Porcupine; twenty agents; D-TEST-11 (≤43 KiB per push per drive).
- **Still open:**
  - Disclosed (Q-EVS-6): a never-read path's version at first pin, and any path's after a re-pin past 4 MiB, rests on evs.
  - Removed holders can test guessed pre-epoch and branch names ([§11.5](DESIGN.md#115-x2-what-the-server-sees)); erased ciphertext waits for v1's compaction.
  - Counsel confirms owner decision 133 before holds (M5); X13's clusters pass §22's suite and §11.13's benchmark before production storage.

### 9.8 evs backend: the file clusters and the write governor

evs stores segments on an HDD cluster and metadata on clusters of 8 × PM9A3 at EC:4, where a governor keeps all but P0 writes within 0.8 DWPD and 50% of rated write IOPS.

- **Code:** `server/cli/evs` hosts `sidecar/evsservice`; taskworker runs the governor loop per metadata cluster, GC and evacuation; `ServiceHost.Blobs` gains If-Match, streamed put, ranged get and delete (X13), over D-OPS-20's MinIO build in the `minio` fork.
- **Lands:** M2 (governor, GC, evacuation; staging cluster); M3 (production cluster, budget live); M10 (purge, drop jobs).
- **Read first:** [§19.6](DESIGN.md#196-the-file-cluster-x13), store rules, clocks, counters; [§11.13](DESIGN.md#1113-backend-iops-gc-quotas-durability), budget, GC, uploads; [§22.8](DESIGN.md#228-load-soak-failure-injection), FS-61, FS-116 to FS-119; [§19.9](DESIGN.md#199-capacity-and-cost-drivers), growth; [§11.21](DESIGN.md#1121-risks), P0 storms.
- **Build first:**
  1. `ServiceHost.Blobs`, D-OPS-20's MinIO, §22.9's suite (M2).
  2. Drive counters, governor loop, per-network WFQ; FS-116 first (M2).
  3. Receipts, hourly evacuation, `pidx/`, orphan pass (M2).
  4. `nvme` run: block size, price table, P0 warn line (D-TEST-11; M2 exit).
- **Easy to get wrong:**
  - Pay P2 once: P1 admission prepays its P2 work into W; funded P2 spends only A2 = min(W, B − T − priced bytes in flight), never T (D-EVS-33, FI-14).
  - P0 never waits; B floors at zero; P0's excess is forgiven, never repaid (owner decisions 186, 190).
  - DELETE is unconditional: until a build passes FS-114, no collection window opens and purges and drops delete nothing (D-OPS-20). Clock offset unknown or over 50 ms: GC deletes nothing.
  - Container, then create-only `pidx/` entries, then delete what they replace (I-EVS-7); P2 rereads `repo/` when issued.
  - Orphan GC needs its 25 h mark, a fence on each ref idle since its 24 h mark, the request deadline and a second check; pushes adopt only uploads under 24 h old (I-EVS-5).
  - No pools on either cluster (owner decision 145, FS-63).
- **Gated by:**
  - FS-116 first, with FS-61, FS-117, FS-118 (FI-14; M2-out).
  - `nvme`: ≤ 43 KiB a push per drive at 2× year one, ≤ 50% of rated IOPS, no push refused (D-TEST-11; M2 exit).
  - FS-114 per build, upgrade and cluster; StoreSettle.tla (M2-out).
  - FS-119 (M3-out); D-TEST-13, FS-81 (M10).
- **Still open:**
  - Q-EVS-24: a P0 storm wears drives past 1 DWPD and stops pushes and evacuation, batches passing 26 h.
  - §22.8's records per batch size year two (five to six sets).
  - Q-OPS-2: §19.9's hdd trigger; segment placement must precede year two's HDD load.

### 9.9 Search: the encrypted index and remote search

Committers' pushes update a repo's encrypted, versionless trigram index; devices search it locally, app hosts optionally via a designated indexer; evs never sees a query.

- **Code:** sidecar root `evs_index_*.go`, `search_*.go`, `search_remote_*.go`; `sidecar/protocol/evsindex.proto`, `search.proto`; §5.9's `search/` cache; `evsservice`'s INDEX_EPOCH check; C19 in connect.
- **Lands:** M2 reserves `.ur-index/`, `ur/index`, `index_epoch`; M10 the rest; remote search at the later of M10's exit and M8's (app hosts) or M6's (team indexers) ([§11.22](DESIGN.md#1122-phasing)).
- **Read first:** [§11.14](DESIGN.md#1114-the-encrypted-search-index) (format, upkeep, remote); [§5.9](DESIGN.md#59-local-state-keychain-os-key-stores-recovery) (cache, version table); [§16.10](DESIGN.md#1610-search) (engine, tools); [§6.10](DESIGN.md#610-contracts-and-accounting) (C19).
- **Build first:**
  1. M10 Gn-in: schemas reviewed; IndexRollup.tla passes TLC; FS rows on fakes.
  2. M10: normalizer 1, `testdata/index/` vectors (D-TEST-15), codecs, commit path, merges, roll-up, CUT, reads.
  3. M10: SEARCH serving (Hello bit 0), C19 (55-minute windows, 256 KiB floor; D-PROTO-22), app-host requester (bit 1).
- **Easy to get wrong:**
  - One head per writer (≤ 16,208 B, an entry per `doc_key`), never shared; no diff rests on a head (D-EVS-46).
  - Every index push except a CLOSURE names the head's `index_epoch` or gets 409 INDEX_EPOCH and rebuilds without listed documents; only CUTs move it (I-EVS-17).
  - Pin x/text's module version, ≥ v0.43.0, one Go toolchain everywhere (connect and sdk still require v0.40.0): v0.40.0 composes U+05D2 U+0307 unlike v0.43.0, both reporting 17.0.0 (FI-22).
  - Mask candidates through §5.9's version table (FS-109 fails per-search key collection); "search more" fetches every missing all shard, in fixed order (D-EVS-50, D-EVS-52).
  - Fixed remote sizes: requests 4,016 B, replies steps × 16,384 B, post-parse failures included; no Cancel, early reply or sync before answering (D-EVS-59, D-TEST-16).
- **Gated by:**
  - M10-out: FS-74 to FS-79, FS-83 (FI-24), FS-107 to FS-112, searches checked against `SearchOracle` (D-TEST-14); FS-125's C19 sweep in connect's tests before its `main` merge.
  - IndexRollup.tla (I-EVS-11 to 13, I-EVS-17, FI-19, FI-20) at Gn-in; at Gn-out, index vectors byte-equal on every leg, §22.6's index and SEARCH fuzzing.
- **Still open:**
  - D-TEST-13 gates format 2's freeze: the index puts a push at ~42-45 KiB per drive (2× year one, 4 KiB blocks; ~34-37 on 1 KiB) against 43.
  - Later: word or semantic layer, Elias-Fano, per-field postings (if §22.8 shows need); CLI and browser requesters.
  - Disclosed: failovers and re-established sessions date a remote search (connect-5).

### 9.10 DNS and the TLS edge

Self-hosted, online-signed DNS for `<root>` (ur.network) and `<net>.<root>` zones; the lb's `ssl_preread` split sends `*.<root>` to `tlsedge`, and TLS ends in the listening sidecar, whose CSRs `certs` proxies.

- **Code:** sidecar `dns_`, `tls_` (front), `dnsservice/` (miekg/dns), `tlsedgeservice/`, `certsservice/`; `server/cli/dns` (API blocks, `dnsedge`), `server/cli/tlsedge`, certs in taskworker and api; warp W1 (split, `lbmap`); connect C14.
- **Lands:** M0 renewal, census; M5 signed zone (no DS), split, tlsedge, certs, front; M6 custom domains; M7 TLSA, DS; M9 PTRs ([§12.16](DESIGN.md#1216-phasing), [§13.17](DESIGN.md#1317-phasing)).
- **Read first:** [§12.6](DESIGN.md#126-hosting-the-self-hosted-dns-edge) (write path, signing, restore), [§12.7](DESIGN.md#127-zone-content) (records), [§13.4](DESIGN.md#134-ingress-the-sni-split-ports-proxy-port-80) (split), [§13.5](DESIGN.md#135-tlsedge-the-connection-path) (tlsedge), [§13.8](DESIGN.md#138-certificates) (certificates).
- **Build first:**
  1. M0: renew ur.network to 2036; network_name census; order the dns edge hosts; request the LE override.
  2. M5: platform names and company MX off ur.network (from M2); signed dns edges; NS switch.
  3. M5: bench the split; flip interfaces singly, drained, then held 24 h.
- **Easy to get wrong:**
  - One transaction per write, then a never-lowering script raises `{dns}serial:<root>` (PgBouncer bars LISTEN/NOTIFY); edges never query Postgres (D-DNS-3, I-12).
  - Empty non-terminals block the wildcard, so each carries a copy row answered from `*`'s current records; `*` is never a CNAME (D-DNS-6, D-DNS-11).
  - Only certs writes DNS-01, ≤ 10 per name per hour, 1 h expiry, rewriting when `/dns/ready` answers `stale` (D-DNS-8).
  - tlsedge presents no certificate; its pre-ServerHello alert is `unrecognized_name` for unknown, unpublished and denied names alike (D-TLS-1, D-TLS-3).
  - Dispatch on the signed `AppMode`, never ALPN's absence; no application byte before the audience check (D-TLS-13, FS-34, [§13.7](DESIGN.md#137-the-sidecars-tls-front)).
  - All networks share LE's 50 new certificates per registered domain per 7 days; ephemeral sidecars use GTS or ZeroSSL first (D-TLS-7).
- **Gated by:**
  - Split bench at peak and 786,432 clients (≤ 5% less H1 throughput, ≤ 1 ms more p99): before any flip.
  - M5-out: root signed without a DS; kill switch ≤ 5 s; FS-34; FS-41 and FS-42's M5 steps.
  - M6-out: FS-32, FS-35, FS-122. DS: 30 clean canary days.
  - Fuzz (every `test.sh`): ClientHello split across records vs `crypto/tls`; PROXY v1, v2; DNS feed, validator.
- **Still open:** No Q-DNS or Q-TLS residual. Lead times: LE override (untimed, due M5), HE's reverse delegation (M9 PTRs). Accepted: site or HE outage (owner decision 123). Unset: dns.yml's `signatures_per_second`, `tcp.connections_per_source`.

### 9.11 Mail: outbound, inbound and burners

Outbound mail runs TLS end to end from a desktop-class sidecar through `smtpedge` to the MX, its preamble ZK-proven; mxedge splices inbound TCP 25 by SNI to customer receivers, which deposit it encrypted in evs. Burners share the wildcard MX.

- **Code:** sidecar root `smtp_*.go` (`SmtpSender`), `mail_*.go`; engines `smtpedgeservice/`, `mxedgeservice/`, hosted by `server/cli/smtpedge`, `server/cli/mxedge`; prover and verifier: nested module `smtpproof` (D-SMTP-11).
- **Lands:** M0 `smtpproof`; M5 report host; M7 inbound; M8 BS1 (receive-only burners); M9 sending; M10 mail search; Team items M7-M9 ([§15.17](DESIGN.md#1517-phasing), [§14.16](DESIGN.md#1416-phasing)).
- **Read first:** [§15.4](DESIGN.md#154-inbound-architecture-x6) (SNI routing); [§15.5](DESIGN.md#155-the-receiver-local-smtp-server-listener-certificates) (receiver, labels); [§15.7](DESIGN.md#157-the-mailbox-in-evs) (mailbox, ingest); [§14.4](DESIGN.md#144-connection-model) (TLS levels); [§14.5](DESIGN.md#145-the-preamble-and-what-makes-it-trustworthy-x7) (proofs).
- **Build first:**
  1. M0: `smtpproof`, on the sidecar's own TLS client (Go's `KeyLogWriter` never exports TLS 1.3's HS).
  2. M5: the `rpt.bringyour.com` platform listener and report intake, before any public name (D-MAIL-10).
  3. M7: the router; the receiver on go-smtp's `ServeConn(conn, ServeConnOptions{AfterStartTls: true})`, since `Serve` always writes a 220 (D-MAIL-3).
- **Easy to get wrong:**
  - `250` only once the deposit is durable; accepted mail never bounces; no authentication result refuses mail (D-MAIL-5).
  - Authenticate at reception within 8 DKIM signatures, 8 ARC sets, 64 queries, 30 s, 8,192 B of evidence; a cut check is no result (D-MAIL-14).
  - Plaintext gets `451 4.7.0` within 1 h of a closed handshake from the sender's /24 or /48, else `530 5.7.0`; any byte between STARTTLS and its 220 resets (D-MAIL-2).
  - smtpedge forwards a client record only once a verified part covers it; a message record, only once parts cover every earlier server record (E3, D-SMTP-22).
  - SPF never aligns; only strict DKIM separates networks (D-SMTP-5). A replying burner's `_domainkey` child blocks the wildcard; its `<blabel>` gets MX and A/AAAA copies ([§15.9](DESIGN.md#159-burner-email), D-DNS-11).
  - No label claims path confidentiality or, for burners, cites MTA-STS (owner decision 135, D-MAIL-13).
- **Gated by:**
  - M5-out: FS-39's intake cases; S7's SNI-less abuse@`<root>`.
  - M7-out: FS-13, FS-33, FS-121, FS-39's rest; the census run ([§23.6](DESIGN.md#236-decisions-that-block-each-milestone)).
  - M8 (BS1): the mail-indexer paths and prompt pass §22.
  - M9: `smtpproof/SPEC.md` frozen at entry; D-SMTP-16's soundness, speed, coverage and interop; a mutated witness per E1-E3, Z1-Z9 ([§22.10](DESIGN.md#2210-internal-review-gates)); FS-31, FS-123.
- **Still open:** the owner's BS1 call on M7's measured SNI loss (proposed: under 5% of sign-up and code mail lacks SNI; D-MAIL-9); HE's TCP 25 egress and reverse delegation, asked in M0, unknown, due at M9's entry review ([§23.7](DESIGN.md#237-external-lead-times)).

### 9.12 MCP, harnesses, the record and the team directory

The stdio MCP server inside `ur daemon` that gives Claude Code, Codex and Cursor agents a static tool catalog, with the approvals, use ledger, run taint, harness capture and restore behind it. It also owns `record.proto`, local search and the team directory, which is a team network's coordination log.

- **Code:** sidecar repo: `mcp/` (in `ur daemon`, one go-sdk `ServerSession` per `ur mcp` relay; D-MCP-2); root `record_`, `directory_` and `search_` files; `protocol/record.proto`, `protocol/directory.proto`; `cli/` (`ur`). Server side: only api's `approval_use` table (MG5) and `POST /approval/cancel`; server/mcp stays separate (D-MCP-7).
- **Lands:** M3 core (MCP, R/W tools, hooks, taint, approvals, restore, vault record); O tools M4-M9 with their components; M6 team record and directory on format-1 streams; M10 search tools and the directory's cards, repo files and index ([§16.18](DESIGN.md#1618-phasing)).
- **Read first:** [§16.4](DESIGN.md#164-the-mcp-server-in-the-daemon) (sessions, limits); [§16.6](DESIGN.md#166-local-security) (refusals, approvals, spend check, ledger, taint); [§16.7](DESIGN.md#167-harness-integration-ingest-and-restore) (hooks, ingest, restore); [§16.8](DESIGN.md#168-record-primitives-x20) (`record.proto`, erasure, receipts); then [§16.11](DESIGN.md#1611-the-team-directory) before M6.
- **Build first:**
  1. M3 Gn-in: specify `record.proto` after RECORD.md's review, naming the hashed bytes and reserving `CanonicalAction` field 37 (D-MCP-6).
  2. M3: the `ur mcp` relay into go-sdk v1.7.0 in the daemon (only `ur` links it), `.ur`, then the R and W tools with version-aware results (D-MCP-1, D-MCP-2, D-MCP-13).
  3. M3: `ur install-harness` and `ur hook` for the three harnesses, the redactor and encrypted spool, persisted taint, restore points and `run_restore` (D-MCP-5, D-MCP-8, D-MCP-16).
  4. M3, before M4's first O tools: device, presence and harness approvals, the spend check and the use ledger (I-8, I-9; D-MCP-9, D-MCP-11, D-MCP-12).
- **Easy to get wrong:**
  - Taint is write-ahead: fsync it before untrusted data returns, fail the call if that write fails, and treat a missing run file or an unbound session as tainted (D-MCP-16; TS1).
  - Harness evidence counts only under `harness_ok`: never from `auto`, `dontAsk` or `bypassPermissions` sessions, and in a tainted run only where the matching `requests` rule names harness, never via `evidenceDefault` (D-MCP-9; owner decision 142).
  - Fsync `Reserve` before each effect and never undo it; an uncertain use stays consumed; server-gated uses reserve only until `not_after - 60 s`; the gate serializes racers with `ON CONFLICT DO NOTHING`, never session locks, which PgBouncer's transaction pooling forbids (D-MCP-11; AU1-AU4).
  - Restore reads the local point, never the vault's redacted copy; apply checks the bytes it moves aside, then installs by no-replace rename, since check-then-rename-over loses concurrent writes (D-MCP-8; D-MCP-15; RV1-RV4).
  - Deposit the read receipt and await evs's 200 before decrypting; a first read that cannot deposit is refused (D-MCP-18).
  - Directory prose is untrusted whoever wrote it, returned as stubs unless `untrusted: include` taints first; go-sdk `Instructions` are per `Server`, so keep one `Server` per `claims` text, fixed per session (D-MCP-29; [§16.11](DESIGN.md#1611-the-team-directory)).
- **Gated by:**
  - M3 Gn-out: `record.proto` vectors over stored bytes, fuzzing, FS-25 to FS-29 ([§22.10](DESIGN.md#2210-internal-review-gates)).
  - M3-out: approval suite FS-25 to FS-29 (AD1-AD4, AU1-AU4; FI-7), FS-30's receipts (audit reader at M6-out), restore suite FS-26 and FS-115 (FI-8), hook conformance for all three harnesses.
  - M6: `directory.proto` freezes at Gn-out on FS-84, FS-85, FS-87, FS-88, FS-100 and FS-101's M6 cases, FI-25 and FI-26 among the invariants they check; FS-86 and FS-99 also gate M6-out, FS-86 holding requests and bytes within 1.25× of `DirectoryCostOracle`, a Team-limit miss blocking.
  - M10-out: FS-80 (search scopes equal the oracle; FI-21, FI-23) and FS-110 (cold "search more"; FI-18, FI-23); directory card and index cases at the later of M6-out and M10-out.
- **Still open:** Q-MCP-1 to Q-MCP-9 are decided with no residual. Disclosed residuals: any same-uid process can forge harness evidence, and the design adopts an authenticated hook channel once a harness ships one (owner decisions 47, 75); copies an agent took survive erasure; read receipts are cooperative; identifier fields can carry short instruction-like words. §16.11's cost table is inferred until §22.8's `directory` row measures it (a sharded cards ref follows if it binds); §16.10's search targets await §22.8's search rows.

### 9.13 Bridge: private IPs, subnet routes and port forwards

Each network gets a private IPv4 /16. A router before connect's mux sends overlay and granted-subnet traffic over per-target links; the target's hook passes, maps (DNAT) or denies each flow by signed config-repo rules.

- **Code:** sidecar root `bridge_*.go`; `device/` (`device.Bridge`, imports connect and `protocol/bridge` only); `protocol/bridge/`; `cli/` (`ur tun`, `ur bridge`); connect C5, C6a, C13-C16, C18; sdk `sdk/device_sidecar.go`; server only `network_bridge_share`. No new service.
- **Lands:** M4 same-network v0 (Linux, WSL2; sdk seam behind `EnableBridge`); M6 shares (C18), `ur tun` on macOS, Windows; M8 Apple, app-device hosts, iOS links ([§17.18](DESIGN.md#1718-phasing)).
- **Read first:**
  1. [§17.5](DESIGN.md#175-data-path-and-the-router): router, pins, links.
  2. [§17.6](DESIGN.md#176-provider-hook-and-port-mapping): hook, rules 0-8.
  3. [§17.8](DESIGN.md#178-rules-in-the-config-repo-delivery-engine-disposition): statements, states.
  4. [§17.9](DESIGN.md#179-acl-identity-egress-cross-network-shares-c18): delegations, shares.
  5. [§18.6](DESIGN.md#186-device-abstractions-and-the-deviceremote-mirror): the sdk seam.
- **Build first:**
  1. M4: `bridge.proto` (Signed 0x1901-0x1908, `BridgeState`, `Pending`).
  2. M4: connect C5's hook and dial fence; C13's delegation seal.
  3. M4: `device.Bridge` (Classify, pins, links, `BridgeEgressPolicy`), then the sdk insertion after `sendRoute.Load()` and `ur tun` on Linux.
- **Easy to get wrong:**
  - Revocation swaps the policy before `CloseFlows`; flows register rule tag and generation before dialing, re-checked before the first byte (D-BRIDGE-21).
  - Admit native flows only on a verified customer-signed `WindowDelegation`; C13's seal is a consistency check (D-BRIDGE-17).
  - Pending denies every private destination and exit; unsigned input never lowers a verified state (D-BRIDGE-18).
  - Rule 0: never dial the daemon's own listeners, document or not (D-BRIDGE-19).
  - Links: `FixedWindowSize: 1`, `PostQuantumEncryption`, `EnableIcmp`; never `DefaultMultiClientSettings` (Q-BRIDGE-2).
  - Pins key on (source, destination, protocol); a full table refuses nothing (D-BRIDGE-7, owner decision 66); HA never falls back to a broader prefix or default route.
- **Gated by:**
  - M4-out: FS-38 (native IP trust; shares M6-out) and FS-56 (dial fence, TCP, UDP, ICMP), both FI-11.
  - [§22.5](DESIGN.md#225-component-matrix-and-hot-path-gates)'s §17 row: Classify (bart v0.30.0, else in-repo) vs linear scan, ≤50 ns at 1,000 prefixes; `BridgeEgressPolicy` vs reference, also fuzzed.
  - §22.7's pin, drain and fragment cases; §22.9's 1,024-slot pin table churned past 1,024 pairs refuses none.
- **Still open:** No Q-BRIDGE residuals. Evidence gates: iOS links await §22.9's memory measurement (owner decision 100); `auto` addresses await the WebRTC overlay test (§17.17); C6a drops 100.64/10 after a release of shadow counts.

### 9.14 SDK, apps and the extension

This area binds the sidecar into the sdk: the `sdk.Sidecar` API apps call, a keyless device role in network processes, wake pushes, and a browser sidecar (`sidecar.wasm` behind the key origin `https://sidecar.ur.io`).

- **Code:** sdk `sdk/sidecar*.go`, `sdk/device_sidecar.go` (`deviceBridge`); leaf `sidecar/device` over `sidecar/protocol/bridge`; Worker main `sdk/js/cmd/sidecarwasm`; `ur native-host` (`cli/`); api `/sidecar/push-token`, `/sidecar/close`; taskworker's push sender and reaper; mmm's key origin.
- **Lands:** M1 lease; M3 credential releases; M4 dark seam, host list, page Worker (RS1); M6 console; M8 app hosts, wakes, native companion; M10 search; Later the extension's Worker ([§18.17](DESIGN.md#1817-phasing)).
- **Read first:** [§18.4](DESIGN.md#184-roles-placement-identity) (roles, budgets); [§18.10](DESIGN.md#1810-build-and-size) (legs, size); [§18.6](DESIGN.md#186-device-abstractions-and-the-deviceremote-mirror) (seam, posture); [§18.8](DESIGN.md#188-the-browser-sidecar-x14-the-extension-and-urio-pages) (key origin, lease); [§18.5](DESIGN.md#185-sdksidecargo) (API, states).
- **Build first:**
  1. M1: `network_client_lease`, the reap predicate, `POST /sidecar/close`; `make check` on the `sidecar_http` leg.
  2. M2: measure `sidecar.wasm` unstripped against 41,943,040 B; Q-SDK-1's spike before M4's entry.
  3. M3: desktop app and extension releases stop persisting `by_jwt` (D-SDK-11).
  4. M4: `sidecar/device`'s dark seam behind `EnableBridge` (posture, zone call, id refusal); `make size`.
- **Easy to get wrong:**
  - `sidecar/device` imports only connect and `sidecar/protocol/bridge` (D-SDK-20); the page Worker links no connect package: connect-facing and `host_*.go` files are `!sidecar_http` (D-SDK-19).
  - Posture (legacy → pending → enforcing) persists and is restored before the first packet; no restart, delay or unsigned response lowers it (D-SDK-13; DP1).
  - Only a verified `SidecarRevoke` means revoked; a confirmed 401 means unenrolled, only if `IsAuthLogoutCurrent(g)` (D-SDK-14). `SidecarKeyStore` never throws (D-SDK-15).
  - The device RPC gains only status, state and delegation calls (`DeviceRpcVersion` stays 3); delegations ride a direct reverseCall, never reverseNotify (D-SDK-3, D-SDK-13).
  - postMessage only from exactly `https://ur.io`; one Worker per network under a Web Lock (D-SDK-18); the key-origin document holds the close capability (D-SDK-17).
  - Wakes carry topic class and version, never an id (WK4); no script spans two hash slots (WK1); a vendor 410 tombstones only while `rev` equals the `tokrev` read (D-SDK-16).
- **Gated by:**
  - `make check` (from M1), `make size` (≤1 MiB, from M4), the wasm gate (from M2) ([§18.10](DESIGN.md#1810-build-and-size)).
  - [§22.5](DESIGN.md#225-component-matrix-and-hot-path-gates)'s §18 row (key-store statuses through every adapter); [§22.9](DESIGN.md#229-conformance-and-platform-budgets)'s Browsers row (M4).
  - FS-37, FS-97 (M4-out); FS-98 (M3-out); FS-36, FS-120 (M8-out); FS-77, FS-83 (M10-out; app hosts at the later of M10-out and M8-out).
- **Still open:**
  - Q-SDK-1's spike decides C17, for the extension only (owner decision 22).
  - `sidecar.wasm` (estimated 13-21 MB) may miss 41,943,040 B; RS1 then ships under 74,965,628 B.
  - Search targets need surrogate and Safari-wasm runs before M10's exit (D-SDK-25).

### 9.15 Server services and operations

This area puts every sidecar service on warp and runs what lies under them: the two on-site MinIO file clusters (X13) with their deadline, settle and write-budget rules, host clocks, migration groups, Redis, the daily sidecar dump, gates, paging, SLOs and runbooks.

- **Code:** server: each service is `server/cli/<svc>` plus a block in `vault/<env>/services.yml` (gkm is `server/cli/gkm`, D-OPS-2); taskworker runs the push sender and the write-budget and HDD loops; pending migration groups live in `server/db_migrations_sidecar_pending.go` (build tag `sidecar_pending`). Gates: `config/<env>/sidecar.yml`. W1-W11: warp. xops: `file-clusters`, the sidecar dump, planetoid's `pg-sidecar` stream. minio: D-OPS-20's MinIO build, on the fork's `sidecar` branch (owner decision 195; [services table](DESIGN.md#services-and-config)).
- **Lands:** M0 dump, W5, W6, hardware order; M2 staging cluster; M3 production cluster, write budget, protection states, pager; M5 dns edges (W9), tlsedge (W1, W7), platform listener (W11); M7 mxedge router; M8 push sender; M9 smtpedge; M10 `format2` gate; each MGn at Mn's Gn-out ([§19.11](DESIGN.md#1911-environments-gates-rollout)).
- **Read first:** [§19.4](DESIGN.md#194-service-blocks) for blocks, mounts and the push sender; [§19.6](DESIGN.md#196-the-file-cluster-x13) for clusters, settle, clocks, budget, durability and the dump; [§19.7](DESIGN.md#197-postgresql-and-redis) for MG0-MG9 and Redis; [§19.11](DESIGN.md#1911-environments-gates-rollout) for gates, rollout classes and order; [§19.10](DESIGN.md#1910-failure-modes-and-runbooks) for runbooks and restore order.
- **Build first:**
  1. M0: MG0 (D-PHASE-3's early merge); from its Gn-out the nightly sidecar dump (02:30-02:50 UTC, 14 generations) and the main dump's exclude list (D-OPS-18); W5, W6; the hardware order; HE's port-25 and reverse-delegation request.
  2. M1-M2: chrony on the evs, gkm, taskworker, Redis and storage hosts before evs serves; D-OPS-20's MinIO build; the staging cluster on the production hosts' PM9A3 set, with drive counters, for D-TEST-11.
  3. M3: staging rebuilt empty and SMART-rechecked (D-PHASE-7); production with the write budget, protection states and two-person pager (owner decision 143); restore and re-seed drills before the pilot.
- **Easy to get wrong:**
  - Deployed MinIO lets a cancelled write land after a later request on its key, even with the lock held to the 30 s drive timeout. Every request but a streamed segment PUT sends `x-ur-deadline-ms` (else 10 s); until a cluster's build passes FS-114, taskworker opens no collection window and purge and drop delete nothing (D-OPS-20, FI-30).
  - Clock offset is measured offset plus root distance, unknown after 3 s without a reply. Unknown or over 50 ms: evs answers pushes 503, GC deletes nothing, and a MinIO host takes no deadline request and begins no drive commit ([§19.6](DESIGN.md#196-the-file-cluster-x13)).
  - No pools on any cluster: a PUT checks preconditions only in the pool it picks (owner decision 145; FS-63). The first cluster keeps `place/`, `proj/`, `projrows/`, `rev/` and `hold/` forever; losing it stops writes on every cluster.
  - A group enters the migrations slice only in its own Gn-out commit and never changes; until then the pending file appends it in the slice's initializer (an `init` append escapes the catalog's alias), which panics outside local, canary or tests (D-OPS-6; owner decision 118).
  - No dump holds a table whose §2.8 ttl is ≤ 7 d, and Redis bundles drop the sidecar families (D-OPS-16, D-OPS-18). Restore the main dump, then the sidecar dump; the abuse step runs before any block reads them; push-token revs rise by 2^32.
  - New blocks: `GET /status` on port 80, `{vault: no, config: yes, site: no}`, user 65532, `server.ScrubCommandLogs()` first, public JWKS only (D-OPS-1); sidecar-route hosts log `$uri`, not `$request` (W8); an unclassified service exits 64 (D-OPS-11).
- **Gated by:**
  - FS-114 (head and marker cases M2-out; purge and drop M10-out); `StoreSettle.tla` passing TLC at M2's Gn-in; FS-40, FS-63 and FS-116 to FS-118 at M2-out.
  - D-TEST-11's `nvme` run: ≤ 43 KiB per push per drive and ≤ 50% of rated IOPS at 2× year one (M2's exit; format 1's freeze).
  - M3-out: FS-41 and FS-42 (later steps M5 to M9), FS-50, FS-119, the `hosts` and `hdd` runs; a dump restore at each Gn-out from M3.
  - FS-54 (M1-out), FS-55 (each Gn-out), FS-52 (M5-out); `push` waits for §22.8's test at 2× Y2 hint rates.
- **Still open:** Q-OPS-2's residual, the hdd trigger, from §22.8's admitted `hdd` run (M3). Still to measure: XFS block size (D-TEST-11), reflink and rmapbt, `MINIO_API_DELETE_CLEANUP_INTERVAL`, records per batch per cluster. The segment placement and added HDD capacity must land before year two (risk "High by the model"); the move tool is later ([§19.18](DESIGN.md#1918-phasing)). HE's port 25 has an unknown lead time (M9).

### 9.16 Tiers, quotas, metering and billing

This area sets Community, Pro and Team limits and prices, enforces them, charges sidecar traffic to the transfer balance, and bills Team through Stripe meters.

- **Code:** `config/all/pro.yml`; server/model (pro.go, pro_model.go, `escrowDrawLess`); `sidecar/api_quota.go`, `sidecar/host_quota.go` (`!sidecar_http`); api's `/network/*`, `/sidecar/*`; taskworker's `RollupServiceUsage`, `ReportStripeMeters`, `ReconcileSidecarCounters`, `RefreshTeamTransferBalances`; MG1, MG2, MG6 tables.
- **Lands:** M1 tiers, limits, client counting; M2 debit path, relayed bytes, nightly count; M4 comparator, dark; M5/M7/M9 edge leases; M6 Team billing; M10 format 2's counting.
- **Read first:** [§20.4](DESIGN.md#204-the-tier-table-x16) tier numbers; [§20.5](DESIGN.md#205-entitlement-model) entitlement, overrides; [§20.6](DESIGN.md#206-x11-what-counts-toward-the-transfer-balance) payers, leases, batches; [§20.7](DESIGN.md#207-enforcement-points-counters-downgrade) enforcement, stored count; [§20.9](DESIGN.md#209-team-billing-and-abuse-limits) draw order, meters.
- **Build first:**
  1. M1: `sidecar:` blocks behind `enforce_sidecar_limits`; `NetworkSidecarLimits`; `QuotaRefusal`.
  2. M2: `ServiceHost.Quota` and `UsageBatch` into `service_debit_journal`; the nightly count.
  3. M4: `escrowDrawLess`, its MG6 index and the escrow benchmark, dark.
- **Easy to get wrong:**
  - Only `escrowDrawLess` orders balances, `team_credit` last, via `IS NOT DISTINCT FROM` (`=` misplaces older NULLs); `escrow_draw_order` never turns off while a `team_credit` balance is in window (D-QUOTA-9).
  - Zero refuses creation only, never activation, reads, deletes, erasure or maintenance; a missing price withholds overage (D-QUOTA-2).
  - At the storage limit or spent, only payload-adding writes stop; closures pass within each eraser's allowance, floored at a fixed 4 MiB (D-QUOTA-3; owner decision 146).
  - A `UsageBatch` applies once by `batch_id`; a drop job's id hashes (scan id, cursor range); unanswered batches drop after 10 min (FI-13(a)).
  - Stripe meters cannot change after creation; Checkout's `billing_cycle_anchor` takes a timestamp, the first 00:00:00 UTC after expiry; prices change only at period boundaries (D-QUOTA-8).
- **Gated by:**
  - FS-44, FS-45, FS-47, FS-60 (FI-13): M2-out; FS-47's §21 case M5-out, mail case M7-out.
  - FS-46 (E-a to E-e) and the escrow benchmark (p99 within 5% at 2× Y1, no added Postgres round trip): M6-in; benchmark again at M6-out.
  - FS-43 (no day billed twice): M6-out; FS-71, FS-90, FS-92, FS-112: M10-out or later.
- **Still open:** `storage_gib_month` is unset until priced (owner decision 122), so Team storage is refused past 200 GiB. Later: data-pack auto-recharge, invoicing above 25 seats.

### 9.17 Abuse, safety and legal process

Abuse policy over names, metadata, rates and reports, never content: intake into cases, machine actions with human review and appeals, network standing, legal process and preservation holds. The kills, halts and suspensions it triggers belong to §8-§20.

- **Code:** server, no package named: api's `/abuse/*` routes and §21's seven tables (MG5, migrations ≥926); taskworker's abuse worker; `hold/<network_id>/<case_id>/_` on the first metadata cluster. Config: `config/<env>/abuse.yml`, pro.yml `sidecar_abuse:`; a Web Risk key in vault ([§21.16](DESIGN.md#2116-interfaces)).
- **Lands:** M5 v0, before any public name (holds once counsel confirms); M6 24/7 review; M7 reporters in the census; M8 trusted flaggers; M9 mail ladder, send gate, breakers; M10 held drops ([§21.18](DESIGN.md#2118-phasing)).
- **Read first:** [§21.4](DESIGN.md#214-principles-and-categories) (principles, ladders); [§21.8](DESIGN.md#218-intake-triage-appeals) (signals, clocks); [§21.7](DESIGN.md#217-network-reputation-and-probation) (standing, verification); [§21.9](DESIGN.md#219-legal-process-under-end-to-end-encryption) (productions, holds); [§21.10](DESIGN.md#2110-retention-and-access) (access, restore).
- **Build first:**
  1. M5: the seven tables and five `/abuse/*` routes; `action` staff-only, off the public API; `appeal` never by client token.
  2. M5: intake (`abuse@<root>`, `postmaster@<root>`, `<token>@rpt.bringyour.com`, the form) into `abuse_case`, joined by host or address, headers or edge `connection_id` (24 h), third-party data dropped after the join.
  3. M5: `ScreenName`, `network_abuse_state` and `network_verified` for §8's hard deny and the §12-§15 gates.
  4. M5: the abuse-mailbox record per action and lift; holds only once counsel confirms.
- **Easy to get wrong:**
  - Act on the smallest unit (host, sending domain, label, network), never the root; machines act only on §21.8's signals, each action holding until review within 24 h, business hours in v0 (D-ABUSE-1; owner decisions 95, 134).
  - Holds never block `--now`, the 7-day timer or per-entry erasure. A covered drop commits and reads, lists and bills as finished while its deletions wait; nothing reveals the hold (D-ABUSE-8; owner decisions 133, 184).
  - A restore lifts no action: mail each action and lift off site as it commits; §19.10's abuse step re-applies those mailed after the dump, in mail order, idempotently by `action_id`, before the token exchange reopens (D-ABUSE-7).
  - Tighten only through `network_sidecar_limit` rows citing the case, never forwarding or sockets; `POST /abuse/action` refuses rows setting `evs_closure_bytes_floor` or `evs_closure_uploads_per_s`, or taking `evs_closure_bytes_per_day` below 4 MiB (owner decisions 66, 146).
  - The `abuse` role, separate from ops, reads only by case id or join key; each read writes `abuse_access_log` (D-ABUSE-7).
- **Gated by:**
  - M5's names: intake, the report host, the kill switch (≤5 s) and the pager.
  - M5-out: FS-39's report-intake cases, S7's SNI-less `abuse@<root>`, FS-47's §21 case, FS-48 (hold deadlines), FS-49 (weekend clocks, registrar notices paging), FS-42's M5 step (mailed kills and lifts hold) ([§23.6](DESIGN.md#236-decisions-that-block-each-milestone)).
  - M5-out once M10's Gn-out has passed: FS-92 (a sealed hold looks like none) and FS-66's, FS-69's, FS-76's, FS-78's hold cases.
- **Still open:** counsel confirms owner decision 133's condition and both hold kinds before holds ship (due M5, start M3; [§23.7](DESIGN.md#237-external-lead-times)). No Q-ABUSE residual. Until M6, a wrong off-hours kill holds ~63 h over a weekend (owner decision 134).

## 10. Open items, risks and evidence gates

No design question is open. This is what remains.

**For the owner now:**

- **Create `urnetwork/minio` on GitHub** before any push (owner decision 195).
- **Decide what happens if M2's storage benchmark misses.**
  - The model puts 1 KiB blocks at 33.3 KiB written per push and 4 KiB blocks at 43.5 KiB, against a 43 KiB gate.
  - If the PM9A3 set misses even at 1 KiB, the design names no remedy but waiting (§22.16; the ledger's §6.6).

**Sign-offs that come later, by design:**

- **BS1.** The owner accepts the SNI loss that M7's census measures (owner decision 34; D-MAIL-9).
- **By M5.** Counsel confirms owner decision 133's condition and each hold kind, `preserve_2703f` and `report_2258a`.
- **Q-OPS-3's residual, left to peer review.** The Postgres-held sidecar rows: D-OPS-18's daily off-site dump, whose design closure M0's entry review needs, and §19.10's reconcile.
- **Q-SDK-1's size spike.** It decides C17 (Q-REPO-2), which only the extension's streaming Worker would need.
- **§10.5's residual.** Owner decision 114's read-at-once rule conflicts with reap revocation for agents a Delegation admitted.

**Evidence the design waits for** (the ledger's §6.6). Every throughput, endurance and capacity figure in §11.13, §19.6 and §19.9 is a model inference until these runs replace it:

| When | Evidence |
|---|---|
| M0 | <ul><li>§10.4's MLS subset and KAT started</li><li>D-OPS-18's dump, and the main dump's exclude list</li></ul> |
| M2 entry | <ul><li>`EvsCommit.tla` passing TLC</li><li>The FS rows written as tests</li><li>The vector schemas</li><li>RECORD.md reviewed</li></ul> |
| M2 exit | <ul><li>D-TEST-11's `nvme` run on the PM9A3 set, with its `fold` and `trash` rows</li><li>§10.6's sizes and §19.9's epoch size</li><li>The 0x0010 interop artifact</li><li>The M2 schedules</li></ul> |
| M3 | <ul><li>The `hdd` row, before the segment cluster holds data</li><li>FS-40 on production</li><li>The `nvme` run again, on production</li><li>FS-50's drill</li><li>A sidecar-dump restore drill before the pilot</li></ul> |
| M4 | <ul><li>`make size`'s 1 MiB gate</li><li>Per-target memory, before any iOS bridge link</li></ul> |
| M5 | Counsel's answer on owner decision 133 |
| M6 entry | FS-46 and §20.9's escrow benchmark on M4's dark build |
| BS1 | The owner's acceptance of the SNI loss |
| M9 | <ul><li>`smtpproof/SPEC.md`</li><li>A soundness argument by two people who did not write it</li><li>An independent relation checker</li></ul> |

**Re-checks that reviewers still owe** (the ledger's §8):

- **Fixed items.** Every item marked fixed waits for a reviewer's re-check at the gate it names. The 21 at G0 run beside M0's bootstrap, their findings returning as Q- items (owner decision 193). The largest set is at M2-in: F01-F06, F09, F10, F12, F13, K01, the presence countersignature, CC-01, CC-04, CC-07, and the second round's storage and authority majors. The ledger's §4.6, §6.1 and §6.2 give each item's gate.
- **Never re-checked.** Twelve earlier entries lay outside the final panel's clusters and were never re-checked (ten were fixes; T4-22 and T5-34 were declined as already fixed): T2-17, T2-32, T2-35, T2-36, T2-37, T4-22, T5-06, T5-20, T5-25, T5-30, T5-34 and T5-35.
- **Not yet confirmed.** Every meta-review entry, the v1 additions and the two SDK fixes are "fixed in design, not resolved": no reviewer has confirmed them yet.
- **May be reopened.** Reviewers may reopen the 12 questions that the internal design review of 2026-11-03 closed (§3.11).

**Accepted residuals worth knowing** (the ledger's §7.2 and §7.3; DESIGN.md §2.10):

- **K01.** Storage correctness rests on D-OPS-20's settle rule in the in-house MinIO build (FI-30; `StoreSettle.tla`). Collection, purge and drops wait on it.
- **CC-02.** Year two's HDD PUTs alone fill the 50% admission line. Segment placement and added HDD drive operations must come first, under a trigger.
- **CC-03.** Until the move tool exists, a cluster at 80% raw capacity or 70% of its inodes takes maintenance only. It refuses everything else with 507 CLUSTER_FULL (D-OPS-22).
- **CC-05.** The cross-network boundary holds against a modified reader or a compromised operator, but not both together.
- **Disclosed in §2.10:**
  - a same-uid process can forge harness-prompt approvals;
  - a passive copy of the keychain reads content up to about 37 days after the copy (60 above 50 leaves) while the device runs, and while it does not run, the copied leaf keeps deriving later epochs' keys until the device commits again or a stale Remove removes it;
  - holders of a team's indexer see search words;
  - relays see search timing;
  - a wave of P0 work can push drives past 0.8 DWPD.

**Known gaps in the text and the tests:**

- **Text.** §2.18 does not repeat two residuals the design discloses elsewhere: harness evidence in untainted runs (T3-05) and the sandbox operator (T3-23). §23.4's M7 row and §23's risks leave out single-site DNS (T4-23).
- **Unaddressed.** R3's request to store group members as member ids is still unaddressed. This is disclosed.
- **Missing test cases** named in the ledger:
  - FS-14: a RepoRevoke, an OwnerConfirm, and a rotation covering one of two same-base removals;
  - FS-17: a case that advances independently without conflict;
  - FS-33: R1b's mixed arrangements;
  - FS-41: a crash during a re-seed;
  - the resync half of R2's acceptance;
  - a carrier resolver in the CGNAT fixture.
- **For implementation time:**
  - A retry screen must keep a push's identity while its outcome is unknown. §11.8's retry rule covers the protocol, and §18's copy takes it up.
  - Launch drills must show what users see when things fail and are repaired.
- **`cli/UI.md`.** It is outside any repo, and it lacks `ur devices` and `ur approve`, which D-CORE-20 and D-SDK-30 add.

## 11. Changing the design during implementation

Implementation will find things the design got wrong or left thin. The rules for changing it:

- **Edit the sources, not DESIGN.md.**
  - Section text lives in `design/source/sections/NN-*.md`. The front matter, registers, glossary and appendices come from `design/source/asm/`.
  - `design/source/build.sh` rebuilds DESIGN.md and validates it. Read `design/source/asm/v7/validate_stdout.txt` afterwards.
  - [design/source/README.md](design/source/README.md) explains the layout.
- **A finding that changes a D- item goes back to review as a Q- item** (D-PHASE-2):
  - An unsettled blocker defers only what it blocks.
  - Until the owner decides, text written at a question's recommendation is marked "(proposed; Q-…)" (D-ARCH-4).
  - A technical problem with a PLAN.md statement keeps the PLAN position visible and goes to the owner (owner rule 8).
- **New owner decisions continue at 197.** Each one touches six places, which the source README lists. The validator fails a decision that no section cites.
- **Freezes are real.** After a format's Gn-in its specification is frozen, and after Gn-out its bytes are. Before a final freeze, only local, T3, canary and M2's staging cluster may hold the format.
- **Metadata goes on the list.** Any new server-visible column, Redis family, object family or proto field updates §2.8's list in the same change (I-18). Gn-out checks it.
- **Before each review gate, refresh the checks:**
  - Rerun the superseded-option grep, carry its readings forward (`asm/v7/carry_readings.py`), and read the new hits.
  - Regenerate the text and word checks.
  - Keep the validation clean. D-ARCH-4's assembly check is a G0 requirement.
- **Answer reviews in the ledger.** [DESIGN-REVIEW-RESPONSE.md](DESIGN-REVIEW-RESPONSE.md) answers every review item, and reviewers re-check fixed items at the gates it names. Future reviews get the same treatment.

## 12. Vocabulary for day one

Most come from [Appendix C](DESIGN.md#appendix-c-glossary), which defines 330 terms, each with the section that owns it. The test tiers and migration groups come from How to review's id families, and `preview_networks` and `sidecar_pending` from D-TRUST-3 and D-OPS-6.

| Term | Meaning |
|---|---|
| `Sidecar`, `ur daemon` | The core type `sidecar.Sidecar`: identity, connect client, APIs and keys. The daemon is the per-instance background process that hosts one Sidecar per network (§5.4, §5.8). |
| device role | The keyless half of the sidecar, package `sidecar/device`, which routes bridge flows in network processes (§18.4) |
| 21842 | The one connect subprotocol id that carries all sidecar traffic (§6.4) |
| evs | Encrypted versioned storage: per-repo, encrypted, git-shaped objects in the file cluster (§11) |
| head, push id | A ref's commit point, `head/<repo>/<ref>`, changed only by If-Match; the id of one push, committed only when a head names it (§11.8) |
| segment | An immutable encrypted object of up to 8 MiB holding packed records (§11.6) |
| placement | A repo's metadata cluster, fixed at creation by a create-only `place/<repo_id>` (§11.8) |
| write budget, P0, P1, P2 | Each metadata cluster's limit of 0.8 DWPD and 50% of write IOPS for all but P0 work. P0 (revocations, lifecycle, Removes) is never queued or refused; P1 (pushes) is queued per network; P2 (folds, evacuation, GC) is prepaid by the P1 that causes it, else unfunded (§11.13). |
| gkm | Group key management: the MLS delivery service plus wrapped key generations (§10.6) |
| generation (g) | One version of a repo's key RK_g, rotated on a shrink or expiry and every 30 days (§10.5) |
| ReaderKey, ReaderWrap, KeyDelivery | A reader's signed X-Wing key, valid 7 days; a delivery of RK_g to it for reading without an MLS leaf; the typed body of such a delivery (§10.5) |
| config repo | The per-network evs repo of signed authority records, policy and settings that every admitted sidecar reads (§7.9) |
| authorization log | One hash-chained log per network of projection bases, statements and api's ticks; its position is the projection version (§7.9) |
| genesis | The owner's first device's signed Genesis record, the network's trust anchor (§7.9) |
| Delegation | A signed config record whose key admits up to `max_admits` tagged agents, for at most 90 days (§7.9) |
| presence key | A hardware key proving that a person approved, beyond a same-device prompt; where the signing device registered one, its countersignature guards revocations of other devices, admissions of untagged sidecars and authority changes (§16.6; owner decisions 185, 187, 189) |
| HeadCheck, witness | A peer RPC comparing pins, generations, heads, epochs and vetoes; any other admitted reader whose HeadCheck agrees (§6.4, §2.14) |
| owner-bound repo | A member's vault, mailbox or secret repo, read only by its consented devices, EvsShares and a visible audit reader (§11.12) |
| indexer, IndexerSet | An always-on device its network designates, none by default, to run background services: mail, mirrors and search upkeep. It gains no access. `IndexerSet` is the config statement that designates it (§3.6, §7.9). |
| format 2, versionless | v1's storage format: versionless content, history drops, the search index and git-lfs. Versionless content is purged once a newer version commits (§11.6, §11.7). |
| erasure, CUT | Destroying chosen entries' keys everywhere by a push on the repo's `erasure` ref; with the search index, a CUT goes first on each index ref (§11.12) |
| C19 window | A 55-minute span of a phone-to-indexer search pair whose reports connect withholds to the window's end, at a 256 KiB floor each way (§6.10) |
| sockets, Find | The abstract socket registry and scheduler; the call that returns tickets for one listener of a name (§9.6, §9.8) |
| contract gate | The check, when a contract is created, that the projection allows one client to reach another (§8.10) |
| tlsedge | The public TLS edge: a layer-4 SNI router that never terminates user TLS (§13.5) |
| certs | The certificate service: CSR proxy, renewal, revocation, and sole DNS-01 writer in URnetwork zones (§13.8) |
| dns edge | A dedicated host type that serves `<root>` authoritatively (§12.6) |
| smtpedge, mxedge | The outbound mail edge that splices end-to-end TLS to destination MXs; the inbound edge that splices TLS to receivers by SNI (§14.4, §15.4) |
| mail indexer | A receiver its network designates for mail, the only path by which the network receives reliably (§15.6) |
| burner | A generated address `<name>@<blabel>.<net>.<root>` under the network's wildcard MX (§15.9) |
| announcement | A team-directory item stating who, what and where for a run, worker or repo (§16.11) |
| RS1-RS3, BS1 | recURd's three release stages, and the burner launch (§23.4) |
| G0, Gn-in, Gn-out | The review gates: G0 before code, then each milestone's entry and exit reviews (§23.8) |
| FS-n, FI-n | Fault schedules, and the invariants they check (§22.8) |
| T1-T6, MG0-MG9 | Test tiers (§22.4); migration groups (§19.7) |
| `preview_networks`, `sidecar_pending` | The config list that limits enrollment until stage 2 (D-TRUST-3); the build tag that keeps a migration group unregistered until its Gn-out (D-OPS-6) |
| `<root>`, `<net>` | The user-content root, ur.network (owner decision 13); a network's opaque, immutable label (owner decision 14) |
