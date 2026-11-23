# Sidecar: implementation review handoff

*2026-11-21, 17:53 (UTC−6), updated as the draft ended; first written 2026-11-20 at 13:40. From the build to the peer
reviewer.*

[HANDOFF.md](HANDOFF.md) handed the design to the implementation team. This document hands the implementation to
its reviewers. It summarizes:

- what was built and where it lives;
- how it was built and checked;
- what is known to be missing;
- where a reviewer's time is best spent.

The draft has ended, and the numbers below were true at this update.

## Contents

1. [The short version](#1-the-short-version)
2. [Repos and branches](#2-repos-and-branches)
3. [The sidecar module](#3-the-sidecar-module)
4. [The server side](#4-the-server-side)
5. [How the work was built and recorded](#5-how-the-work-was-built-and-recorded)
6. [Testing: tiers, commands and rules](#6-testing-tiers-commands-and-rules)
7. [Known gaps: the review's agenda](#7-known-gaps-the-reviews-agenda)
8. [A suggested review order](#8-a-suggested-review-order)
9. [Before anything deploys](#9-before-anything-deploys)
10. [What happens next](#10-what-happens-next)

## 1. The short version

- **What this is.** It is a draft of DESIGN.md's milestones M0 to M10. That is the end-to-end encrypted substrate under
  recURd and burner email, built on the `sidecar` branch of each repo it touches. The owner set the run's shape on
  2026-11-07: draft the whole surface first, then a review phase for integration tests and debugging, then app UI.
  This document opens the review phase.
- **What "drafted" means.** For each piece of work:
  1. An agent built the track from its brief and wrote its tests.
  2. The track landed through `track-land` once it compiled and its tests and `landcheck` passed: the sidecar module,
     plain and under `sidecar_testhooks`, plus the packages it touched in other repos.
  3. After it landed, `tip-check` reran the module's whole check at each new sidecar tip (section 6).

  The build ran second-agent reviews only on 2026-11-06 and 2026-11-07, for about 50 early tracks, most of M0's
  bootstrap, before the owner switched the run to drafting. Every build track since then, roughly 700, is its author's
  work alone; no reviewer read it before it landed. Treat every claim in a commit message or a track report as the
  author's claim.
- **One peer review so far.** A reviewer read the draft on 2026-11-20 with this document's first version and wrote
  `REVIEW.md` in the build's sidecar checkout. It is not committed, so ask for a copy. It found release blockers at the
  entry points: the first owner's flow could not publish its initial config from the stock daemon and API, and evs,
  scoped service tokens, socket publication and SMTP had entry-point gaps of their own. A separate session, not the
  build's, then fixed its findings as `review-fix-*` tracks. They landed on sidecar from the evening of 2026-11-20 into
  2026-11-21, and in server, sdk, connect, build, warp, xops and mmm too. The owner closed that review on 2026-11-21
  with its changes merged. Their commit messages are their record. Four questions it left open were then decided as
  QD-1162 to QD-1165 (owner decisions 677 to 680) and built by the build's tracks. Section 7 says which of the first
  version's gaps that work closed.
- **How much.** The plan has 923 tasks across 24 areas:

  | State | Tasks |
  |---|---|
  | Done | 18 |
  | Drafted | 897 |
  | Landed with an item still open | 3 |
  | Held by a decision deferred to Later | 5 |
  | Running | 0 |
  | Stuck | 0 |

  M0 to M3, M5 and M7 to M9 are complete. M4 is at 60 of 61, M6 at 103 of 105 and M10 at 132 of 134. The five
  missing tasks are the held ones: QD-1038's two (PROTO-M10-05, QUOTA-M10-02), QD-1032's (TEST-M6-03), QD-047's
  (EVSB-M6-01) and owner decision 279's (MCP-M4-03).
- **What landed since the first version.** The build's last tracks, among them:
  - `mcp-m7-01`, for MCP's mail tools and format-2 evs tools (MCP-M7-01, MCP-M9-01 and MCP-M10-01);
  - `fault-clause-registry` (QD-1084) and `fault-package-run-time`, which sends the fault rows' runs to child
    processes;
  - the erased-version readers (QD-1145, QD-1156 and QD-1157);
  - erasure completion (QD-1137, QD-1158, QD-1160, QD-1161 and QD-1166 to QD-1169);
  - darwin's ICMP echo identifiers (QD-1159);
  - three sdk tests that had gone red unseen (`sdk-root-tests-red`).
- **Health.** `tip-check` (section 6) was green at sidecar `515c42f9`. The `sidecar` branches were last pushed to
  origin at sidecar `515c42f9`. `main` is untouched in every repo, and nothing is deployed.
- **Decisions.**
  - Owner decisions run to 684.
  - The build's question ledger runs to QD-1169.
  - Since 2026-11-16 the owner's standing instruction has been to accept each question's recommended option. So most
    late QDs were answered that way, recorded, and turned into fix tracks.
  - The final design sweep (`dr9-final-sweep`, then `dr10-late-fold` to `dr13-late-fold`, all 2026-11-21) folded
    every decision through QD-1169 into DESIGN.md, DESIGN-DETAILS.md and RECORD.md. Two wait: QD-024 for the
    owner's `design/UI.md`, and QD-1086 for KEYS's review-phase rework.
  - [DESIGN-AMENDMENTS.md](DESIGN-AMENDMENTS.md) holds decisions that [DESIGN.md](DESIGN.md) does not have yet, and
    [DESIGN-DEFER.md](DESIGN-DEFER.md) holds what was put off.
- **Where to start.** Read `REVIEW.md` if you can get a copy, then section 7: the review fixes closed much of the
  first version's largest gap, host composition, and what is left is listed there. Then follow section 8's order.

## 2. Repos and branches

Each repo below has a `sidecar` branch. The counts are commits without merges since the branch left `main` (or the
fork's default branch), and the size of the diff.

| Repo | Commits | Diff | What is there |
|---|---:|---|---|
| sidecar | 3,326 | 6,732 files, +1.81M / −8.9k | The new module: the core, the `ur` CLI, MCP, the service engines, the test worlds and the design sources. The size includes vendored `third_party/` and generated protobuf code. |
| server | 987 | 1,567 files, +414.7k / −1.3k | The service blocks and their hosts, team and ACL state, mail, dns, abuse, quota, `sidecarctl`, the gate tool and the T3 tests (section 4). |
| sdk | 186 | 242 files, +85.8k / −10.6k | `sdk/sidecar.go` and the app-facing bindings (mail, directory, search, state events). |
| connect | 177 | 125 files, +41.6k / −11.9k | The default-off connect changes (the C-numbered list in §4.18), and the API spec `api/bringyour.yml`. |
| warp | 73 | 82 files, +25.4k / −924 | `services/sidecar-blocks/` fragments, the lb's `internal_routes`, warpctl. |
| minio (fork) | 47 | 92 files, +18.7k / −273 | The `urnetwork/minio` fork's changes for evs's storage. |
| xops | 61 | 118 files, +13.2k / −260 | Ansible plays: the edges play, the dbs play (PgBouncer entries, HBA rules, slot budget) and the Redis backup filter. |
| build | 51 | 93 files, +10.3k / −107 | Release Makefiles and the pending-tag guard. |
| mmm | 31 | 114 files, +10k / −93 | ur.io's `install.sh` and its OAuth consent page for `ur login`. |
| operator-core | 9 | 38 files, +4.5k | The host contract (owner decision 251): package `operator`'s `Env`, its global env (QD-1027), and the quota refusal and limits types. |
| config, sn, tests | 29, 14, 5 | small | Settings, the sn changes and test fixtures. |
| glog, userwireguard, proxy | 1 each | one line | The Go 1.27.4 line (QD-674). |

DESIGN.md is generated from `sidecar/design/source/`: its 23 section files, and the owner's record of decisions 1 to 684
(`owner/DECISIONS.md`). Code conventions are in [CODESTYLE.md](CODESTYLE.md).

## 3. The sidecar module

HANDOFF.md's [section 3](HANDOFF.md#3-the-system-on-one-page) still describes the system accurately: trust
boundaries, the device and server pictures, the six planes and the thirteen flows. This is the code's map onto it.

| Path | What it holds |
|---|---|
| root package `sidecar` | The `sidecar.Sidecar` core and every client side, by file prefix: `evs_*` (push, read and the verifying reader, erase, export, drops, holds, the index store); `gkm_*` (groups, rotation, re-form, recovery, sync); `acl_*` (policy, compile, evaluation, seats, suspension); `mail_*` and `smtp_*` (receiver, sender, outbox, erasure, DKIM keys); `search_*` (engine, remote serve and ask, index writer); `directory_*` (cards, runs, workers, erasure, revocation); `record_*` (recURd's record writer and erasure); `daemon_*`, `config_*`, `bridge_*`, `tls_*` and the settings objects. |
| `cli/` | The `ur` CLI: `ur daemon`, `ur mcp`, `ur hook`, `ur admin ...`, `ur evs ...` and the rest. `cli/UI.md` records the interim spellings, which the owner's `design/UI.md` will replace (QD-024). |
| `mcp/` | §16's MCP server inside `ur daemon`. |
| `protocol/` | The wire and file formats (`evs.proto`, `record.proto`, `directory.proto`, `bridge/auth.proto` and others), their generated code, and `EVS-FORMAT.md` and `MAIL-FORMAT.md`. |
| `evsservice/` | evs's engine: the push and commit path and its fence, slots, drops and the drop table, holds at the DELETE, the purge, reseed and the budget. |
| `gkmservice/` | gkm's service: generations and claims, re-form, and the reconciler. |
| `socketsservice/`, `dnsservice/`, `certsservice/`, `tlsedgeservice/`, `smtpedgeservice/`, `mxedgeservice/`, `pushservice/` | The service engines that server's blocks host. |
| `smtpproof/` | Outbound mail's proof, which smtpedge verifies before forwarding records. `SPEC.md` is its specification. |
| `device/` | The device abstractions of §18.6, for the apps' sidecar and forwarding roles. |
| `mlsinterop/` | The MLS subset's interop. It is dark: QD-1040 set MLS aside for Later, and v0 uses KeyDelivery wraps. |
| `check/` | Repo-wide checks: format fences, `metadata_list.yml`'s rows, and the forwarding legs' closure with its reviewed seams (`legs_closure_test.go`). |
| `sidecartest/` | The T2 worlds and fakes. `fault/` holds the FS schedules, the FI invariants and each gate's sweep (`gate_*.go`). `model/` holds the TLA+ specs (`EvsCommit.tla`, `IndexRollup.tla`) and their runner. Also `bench/`, the leak leg and the cross-slot suites. |
| `metadata_list.yml` | §2.8's list of every value any server sees, with its ttl. It is the product's promise; `check/` holds code to it. |

Three things recur across the module:

- **The one rule.** Servers see only ciphertext and the header values the metadata list names (§2.4, §2.5, I-4).
- **Settings objects.** Every limit is meant to be a field with its default (QD-702). Drafted code still has
  constants, and QD-706's sweep is owed.
- **Build tags.**

  | Tag | What it selects |
  |---|---|
  | `sidecar_testhooks` | Barriers and test seams. |
  | `sidecar_check` | The check/ package's checks. |
  | `sidecar_leaktest` | The leak leg's canaries. |
  | `sidecar_localstack` | T3 convention tests. |
  | `sidecar_http` | The js/wasm page Worker leg. |
  | `ios_extension` | The forwarding leg. |

## 4. The server side

| Path in server | What it holds |
|---|---|
| `cli/evs`, `cli/gkm`, `cli/sockets`, `cli/dns`, `cli/dnsedge`, `cli/tlsedge`, `cli/smtpedge`, `cli/mxedge`, `cli/mxedge-platform`, `cli/mcp` | One binary per block. Each reads its service URLs from `UR_API_URL` and `UR_SOCKETS_URL` (QD-1140), and its internal-gate bearer from its scoped vault. |
| `evshost/`, `dnshost/`, `mxedgehost/`, `quotahost/`, `sidecarhost/` | The hosts that wrap the sidecar module's engines for the blocks. |
| `sidecarctl/` | The one operations CLI (QD-750), for example `sidecarctl internal bearer-keygen` and `sidecarctl abuse mailbox-keygen`. |
| `sidecarrestore/` | The restore steps (FS-42). |
| `sidecart3/` and the `*_t3_test.go` files | T3 tests on the private local stack. |
| `local/sidecar-gate/` | The gate tool. `gates.yml` is generated from sidecartest's gate sweeps and covers G0, M0-in to M10, `held`, `every` and `next`. `ops-matrix.yml` is §19's matrix. |
| `local/sidecar-migrations/` | The sidecar migration groups, kept pending under `sidecar_pending` until their gate registers them (D-OPS-6). |
| `model/` | Team, ACL, mail, dns, abuse, quota and directory state, among others. |
| `api/` | api's routes. Every route has an access class in `route_authz.go`. |
| `db/roles/` | The edges' restricted Postgres roles, held to the code by `db_edge_roles_test.go`. |

## 5. How the work was built and recorded

- **Lanes and tracks.** The plan lives in the build workspace's `.stack/plan/`, one file per area (ABUSE, ACL, BRIDGE
  and so on). Work ran in five lanes. Each lane ran tracks in order, and a validator kept two lanes from holding the
  same file at once. A track is one brief's work over one or more repos. Its worktrees are under `.tracks/<track>/`.
  The review-fix session's worktrees are there too, as `.tracks/review-fix-*`.
- **Questions.** An agent that met a choice the design left open stopped and wrote a question, with options and a
  recommendation (`.stack/questions/`). Each answer has a QD number in `.stack/decisions/` (`LEDGER.json`,
  `RESOLUTIONS.md`), and is written back into its question file. Answers that needed code became fix tracks. Design
  text goes into DESIGN.md through design-records tracks.
- **The trail behind a line of code.**
  - Commit messages are long. They name the task (for example `EVS2-M10-31`) and the decisions (QD-n, owner decision
    n) they implement, so `git log -S` and `git blame` usually find the reason.
  - `.stack/state/drafted.txt` holds 998 entries, one per drafted task, each saying what landed and what was put
    off. 749 of them name review-phase work.
  - `.stack/state/review-phase-work.md` holds the owner decisions that place work in the review phase, and the open
    items from each recent track's report.
  - `.stack/state/final-design-sweep.md` holds what the final sweep folded and left, the owner's steps before deploy,
    and the handoff's test notes.

  `.stack` is the build's local workspace, not a repo, so it is not on origin. Ask for a copy if you review from
  origin.
- **Commit rules.** Merge, never rebase. No AI attribution in any commit. Pushes go only to `sidecar` branches, at
  checkpoints. The build's orchestrator made them, and since 2026-11-21 the review-fix session has made them too.

## 6. Testing: tiers, commands and rules

**Tiers** (§22):

| Tier | What it is | Coverage |
|---|---|---|
| T2 | In-process worlds over fakes (`sidecartest`) | Most evidence |
| T3 | The private local stack: Postgres, Redis, MinIO file clusters (`server/sidecart3`, `sidecar-t3.sh`) | Part of the evidence |
| T4 | Physical device cells | Not run |
| T5, T6 | Load and production-like runs | Not run |

**Commands:**

- sidecar: `make check` runs every module's tests plain and under `sidecar_testhooks`, then the leak leg, then
  `check/` under `sidecar_check`. The build runs it with `TEST_TIMEOUT=120m`, since the fault package once outgrew 60
  minutes on this loaded host. `fault-package-run-time` has since cut its hooks leg from 975 s to 561 s.
- server: run tests through the build's `.stack/server-test.sh <server checkout> <go test args>`. It keeps
  `server/test-env.sh`'s guards on.
- Gates: `sidecar-gate <gate> -list` lists a gate's rows. A full run needs the private stores and T3's layouts. M9's,
  M10's and the held gate's full runs have not been taken; only `-list` and direct package runs have.
- `tip-check` runs at every new sidecar tip. It runs:
  - `make check`;
  - server's untagged vet and a set of named audits: the root package's, and evshost's routes against
    `bringyour.yml`;
  - sdk's untagged vet and its whole root package on both legs, less two tests that fail only beside the rest of the
    package (section 7, item 5).

  Before 2026-11-21 it ran only five of the sdk root package's audits, and three of the package's tests were red for
  five hours unseen.

**Rules that bind reviewers as they bound the build:**

- **Never run the whole-suite `server/test.sh`, `connect/test.sh` or `sdk/test.sh`.** They take the shared
  `tests/network-intensive-suite-lock.sh`, which another team's campaign may hold. Run direct `go test` on the packages
  you touch.
- **Never dial loopback ports 5432, 6432 or 6379-6427.** They can be production data tunnels.
- **Keep `server/test-env.sh`'s attestation and dial guards on.** Never set `URNETWORK_TEST_REAL_VAULT`, and never run
  `xops/bin/by-*` scripts or migrations against anything but the private test stack.
- **Never read or copy vault values.**
- **Do not push, merge to `main`, or change anything on a real host.**
- **Leave alone what belongs to others.** The `urnetwork-local-pg` and `urnetwork-local-redis` containers and anything
  started from `~/urnetwork` belong to someone else.

**Failures that come from this host, not the code:**

- **Durable blob tests.** Twenty of them need a Linux ext4 host.
- **Private resources.** `TestIpInfo` and its neighbours need private resources the portable root lacks.
- **`-trimpath`.** Three env tests fail under it.
- **Python modules.** PyYAML and Jinja2 are not installed here, so several xops and connect Python tests cannot run.
- **`build/server`.** It is a stale copy, so the R-OPS-7 and D-OPS-6 matrix rows fail.
- **`auth.yml`.** oauth's twelve DB tests need one.
- **T3's stack.** It records no `settle_passed_build`, so the evs block's purge deletes nothing on T3.
- **Load.** `TestPrivacySearchQueryCanaries` is load-sensitive.

The full list is in the final design sweep's test notes.

## 7. Known gaps: the review's agenda

Each item was checked against the code at this update. Where a fix landed since the first version, the end of this
section says so.

**1. Host composition.** The review fixes wired much of what this item listed on 2026-11-20: search's index writer,
remote serving and scope masks; the record's evs streams, erasure index and component; and the mail sender's runner.
What is still missing:

- **Mail sending.** `SmtpSender` and `SmtpOutboxRunner` are built only when a prover is set
  (`mail_component_smtp.go`), and `cli/smtp_prover.go` returns none while no release pins a key set. So `CheckSend`
  still prices through `p/` records on every host.
- **Executed drops.** Nothing in production calls `EvsClient.SetDropApplier`. A format-2 executed drop meets
  `ErrEvsDropApplierMissing` and never reaches `Sidecar.ApplyExecutedDrop` or the restore-point holder.
- **Team start.** `SaveAclTeamStart` still has no caller. The first Owner's first config head signs the Team starter
  policy instead (307e4ab4).
- **The DNS watch.** Nothing in production builds a `DnsWatch`, so `DnsWatch.StrictChain` answers false.
- **evs mirror views.** `NewRecordEvsMirrorView` and `EvsMirrorStatusLines` have no production host.
- **Mail attachments over MCP.** `mail_read`'s attachment links answer not found, because `MailClient` reads no
  part's bytes.

To find more, search `drafted.txt` for "Nothing constructs", "no Sidecar builds", "nothing calls", "has no caller" and
"not wired". Check each hit against the code: the review fixes wired some after their entries were written.

**2. Owner decisions that put work in the review phase.**

- **QD-1028.** Move server-hosted sidecar code into `sidecar/{model,controller,work,handler}`. It runs as a barrier
  when the next phase starts.
- **QD-1035.** Remove presence-key attestation.
- **QD-1040.** MLS is set aside. Rework key formation onto KeyDelivery wraps, and keep the MLS code dark.
- **QD-706.** The settings sweep.
- **QD-641.** The storage-first engine work.
- **QD-1032.** The dark prefix rules stay off.
- **QD-1067 and QD-1068.**

**3. Gates that read missing or open.**

- M9's and M10's exits and the held gate list many rows as missing:
  - case-tiers with no registered builder: 33 at M10's exit and 17 cases in the held gate when counted on
    2026-11-20. Since then only FS-44, FS-45, FS-47, FS-53, FS-60, FS-61 and FS-116 to FS-118 have gained builders;
  - FI-13, FI-14, FI-25 and FI-26 are not bound. FS-118's case checks FI-14 through a case-local invariant of its own;
  - schedules that name no invariant: FS-99's cards, FS-107, FS-108 and FS-111. The first version also named FS-74,
    FS-75, FS-87 and FS-88, which already had case-local checks then. `gate_held_test.go` still lists FS-87's index and
    FS-88's searches as known failing;
  - S6 has its row in `sidecartest/scenario.go` but no registered test;
  - two inline paths do not call `InlinePath` yet: smtpedge's preamble gate (SMTP-M9-10) and evs's write-budget
    admission (EVSB-M2-06).
- The rows people, hardware or production owe are listed with the owner's steps.
- No T3 row has run the explorer's one-seed short form (owner decision 667), and nothing checks T3's registrations as
  `rules_testhooks_test.go` checks T2's.

**4. Items that deserve a careful eye first.**

- **The shared edge bearer.** tlsedge, smtpedge and mxedge share one bearer class. A stolen one can mark a Team's MX row
  verified or failing.
- **PgBouncer.** Its HBA rules and two `min_pool_size` readings have not been checked against a running PgBouncer 1.26.
- **Completion ERASEs (QD-1137).** A stray completion naming another erasure's key now blocks that erasure only where
  every key it named first was named again (3e04fc2d). evs still refuses a completion on a key whose last naming was a
  completion. Review the rule as a whole.
- **Directory erasure completion (QD-1158, QD-1160, QD-1161, QD-1166 to QD-1169).** It is built and tested on fakes
  only: no real-engine world holds M6 announce entries in a format-2 directory. A person's erasure whose card removal
  meets a path conflict stays incomplete until it runs again under a new id.
- **Git-mode export of an erased blob (QD-1156).** Export writes the blob's stub and rewrites the later commits under
  new oids, noting the originals. It is tested only on a stand-in evs, since no client of this codebase writes a
  git-mode push in a slot-keyed repo. A rewritten commit's gpgsig no longer verifies.
- **`mail_strict`.** The desktop receiver now checks the DNSSEC chain itself (connect 933c06eb, sidecar 4ba6bd62).
  DESIGN-DEFER.md still says C20 blocks `strict_chain`, and `DnsWatch` (item 1) answers false.
- **Policy tests.** An activated route grant meets no `ip:` check. The review-fix session has an open question on it
  (`review-fix-acl-test-activated-route`).
- **MTA-STS.**
  - A verification change with no writer reaches the zone only at the network's next sign-in or payment.
  - The reconcile's post-commit hint takes a pooled connection while its caller holds one.

**5. Test debt.**

- Mutation sweeps beyond spot mutants, fuzzing, exhaustive FS schedules, T3 runs of many format-2 cases, and
  benchmarks.
- Known flaky behaviour:
  - sdk's `TestDeviceLocalCloseAndWaitJoinsCurrentMuxPump` and `TestDeviceLocalCloseAndWaitJoinsRetiredMuxPump` fail
    only inside the whole package, on state other tests leave behind. `tip-check` skips both until sdk-test-isolation
    fixes them. The three sdk flakes found first are fixed; one was a real race, in which a camouflage report could go
    out under the next account's token.
  - `sidecartest`'s `FakeClock.Advance` can set the clock back under two movers.
- The fault package keeps five schedules whose connect clients ran in one process (FS-17, FS-38, FS-56, FS-98,
  FS-124). Darwin's ICMP fix (QD-1159, connect 7a8f2a3b) removes the reason, so they can move to child processes.

**6. Spec and doc drift.**

- `bringyour.yml` still words its 402 answers "with terms" (the segments PUT and the push POST).
- DESIGN-DEFER.md's C20 line (item 4).
- RECORD.md 5.7's open BASE row stays open, because `record_md_test.go` holds its sentence.
- The rest of what the final sweep left is in `.stack/state/final-design-sweep.md`.

**Fixed since the first version.** These no longer need a look:
- held drop jobs that lost their hold on a failed resume (c834387b, 5114b0fa);
- `IndexEraser`'s completion on real evs, where `Retained` always answered incomplete (3e04fc2d);
- `TestEvsMapperUploadsPartsAtOnce`'s hang (e6d91cc1);
- `bringyour.yml`'s evs refusal bodies and its served-set gap, and `check-routes.sh`'s blind spot for routes registered
  through `Routes()` (bc3d9488, bc8ab84d);
- QD-1084's clause registry, which has landed (its leftovers are in `review-phase-work.md`);
- most of item 1.

The review phase list in `.stack/state/review-phase-work.md` has each item with its source; `drafted.txt` has the
rest per task.

## 8. A suggested review order

Ordered by what a mistake would cost:

1. **The one rule and the metadata list.** Read `metadata_list.yml`, then `check/`'s fence and metadata tests. Look at
   every server-visible column, Redis key and log field, against D-TRUST-1 (a malicious, possibly compelled server)
   and I-4.
2. **evs.**
   - The push and commit path and its fence: `evsservice/push_commit.go` and `check.go`.
   - The formats: `protocol/evs.proto` and `EVS-FORMAT.md`.
   - Drops and holds: `drop_table.go`, `drop_job.go`, and the hold read at each DELETE.
   - Erasure and completion.
   - The verifying reader: `evs_reconstruct.go` and `evs_read_erased.go`.
   - `sidecartest/model/EvsCommit.tla` states the commit's properties. TLC reruns at the tip are owed.
3. **gkm and keys.** Generations and claims (`gkmservice/generations.go`); rotation, re-form and resume
   (`gkm_rotate.go`, `gkm_reform.go`, `gkm_sync.go`); recovery.
4. **ACL and teams.** The policy compiler and evaluator, seats, suspension and Team start.
5. **Mail and SMTP.** smtpproof and its `SPEC.md`; smtpedge's gate (`smtpedgeservice/gate.go`); mxedge's receivers and
   report intake; the sender and outbox; DKIM keys and custom domains.
6. **Abuse (§21).** Standing, suspension's effects, the mail pass and notices.
7. **DNS, certs and tlsedge.**
8. **The sdk bindings and the forwarding leg.** The forwarding leg is the `ios_extension` closure and its reviewed
   seams.
9. **Operations.** The warp fragments, the xops plays, PgBouncer, the roles, the Redis filter and §19's matrix.

## 9. Before anything deploys

Nothing in this list is done, and none of it is the review's to do. Each step is the owner's, at deploy, and the full
list with each step's order is in the final design sweep's owner steps.

- **The edges' restricted Postgres roles** (tlsedge, mxedge, smtpedge):
  - run their SQL and add their vault files;
  - add their PgBouncer entries;
  - deploy the HBA rules before adding their `userlist.txt` lines;
  - make 33 connection slots of room for the edges' budget.
- **The internal gate bearers** for edge, mxedge-platform, evs and gkm: draw them with `sidecarctl internal
  bearer-keygen`, and add api's verify entries.
- **The lb.** Fill in its allow-list site ranges, deploy its widened CORS list after the review phase (QD-221), and
  rebuild its image and units.
- **Key files.** Draw smtpedge's X-UR-Ref key file before M9's platform fragment. Draw the abuse mailbox's keys after
  the review phase.
- **The competition patch validator.** Record its two digests when it is compiled (QD-874).
- **The Redis backup filter.** Deploy it.
- **Postmaster tools.** Register them.
- **The CLI's spellings.** Supply the owner's `design/UI.md` for the CLI's final spellings.
- **What production and hardware owe.** Soaks, the T4 to T6 runs, and the people's sign-offs that the gates read as
  open.

## 10. What happens next

The draft ended with:

1. **The final design sweep.** `dr9-final-sweep` and `dr10-late-fold` to `dr13-late-fold` folded every decision
   through QD-1169.
2. **A green tip-check**, at sidecar `515c42f9`.
3. **The last push of the `sidecar` branches**, at sidecar `515c42f9`.

The owner's first instruction for the next phase (2026-11-21) is end-to-end integration tests for the new server
services. They spin up all the server services and their clients and test concurrency, in the manner of
`server/connect`'s and `server/proxy`'s tests.

Progress at this update (2026-11-23), in `server/sidecare2e` and `server/sidecart3` (plan: `.stack/state/e2e-plan.md`):

- **The scenarios.** Eight cases run every block's host in one process, with real sidecar clients on real keys, chaos
  restarts of hosts and devices, and ledgers that reconcile exactly:
  - evs (`TestE2eEvsConcurrency`): many writers on one repo, exact-head races, drops, holds and erasure, evs restarts;
  - gkm (`TestE2eGkmConcurrency`, with its re-form and second-device cases): membership churn, rotation races,
    re-forms under contention, gkm restarts;
  - the owner's "blogger" case and "it bridge" case, the second now with no stand-ins left;
  - mail (`TestE2eMailConcurrency`), group mailboxes included;
  - dns and certificates (`TestE2eDnsCertsConcurrency`): the real certs worker against an in-process Pebble, dnsedge
    serving the challenges, and the desktop orderer's delegated DNS-01 path;
  - the control plane (`TestE2eControlPlaneConcurrency`, with chaos and quota cases), on a team network of several
    members and tagged sidecars;
  - churn load (`TestE2eChurnLoad`): fifteen worker kinds over rounds across every service, then exact ledgers.
- **Where they stand.** All eight passed once on sidecar `c88a64af`, and churn and gkm's side cases passed again on
  later tips. The main gkm case fails about one run in three, on varying checks, and the control-plane harness has a
  sync race when a member is removed; `e2e-flakes-final` is sorting both into case timing or product. Each case's
  file header lists its findings, fixed or open.
- **What they found.** Dozens of product bugs, each fixed on the `sidecar` branches or queued. The most serious, all
  fixed:
  - revoking the device that signed a network's ServiceSettings or VersioningRules forked every device of the network
    at the next base, for good (QD-1207);
  - repo paths untouched for two config bases became unreadable on every device (QD-1178);
  - after an api restart, a personal network whose base its second device signed was never loaded, and its exchange
    answered temporarily_unavailable (QD-1192);
  - published names never resolved to the edge, because nothing wrote the zones' `*` address records, and Team scope
    zones were never written at all;
  - a personal network's second device got no vault scope at the token exchange;
  - group mail answered delivered was lost at ingest (QD-1196);
  - a key rotation racing a re-form stranded a device on the old group (QD-1186 to QD-1188).
- **Decisions.** QD-1170 to QD-1221 were recorded under the owner's standing acceptance of recommended options, each
  in `.stack/decisions/RESOLUTIONS.md`, and design-records tracks have folded them all into DESIGN.md:
  `dr14-late-fold` QD-1170 to QD-1175 as owner decisions 685 to 690, `dr15-late-fold` QD-1176 to QD-1209 as 691 to
  715 (QD-1195, a one-time landing allowance, as an unnumbered owner instruction), and `dr16-late-fold` QD-1210 to
  QD-1221 as 716 to 722:
  - a forwarding role alarms a config generation it cannot open, and a listing off its chain (716);
  - a team member's removal ends the auth keys and API keys it made, so a re-join revives none (717);
  - topic `sock` is a raised clock (718);
  - the stock daemon signs EXACT_HEAD on every head a person's confirmed command saves, `ur bridge block` and a
    revocation's re-signed block included (719);
  - a team's security notices reach its Owners and Admins, and its wallet notices and billing mail its Owners and
    Billing admins, Owners first, each naming its network (720);
  - the account message outbox records a send's outcome on a context made after the send, so a slow send is not
    sent twice (721);
  - an evs statement before a reader's window still meets the refs-table rules that need no right at its pin
    (722).
- **Still to do in this phase:** the queued fix tracks (`.stack/scratch/lanes/pending-fix-tracks.json`) and the plan's
  step 5, a nightly leg that runs a bounded e2e subset and the sidecar-related server packages' own tests.

Then come:

- the rest of the review phase, which this document opens;
- the apps' UI;
- QD-1028's layout move, which runs as a barrier in the next phase.

Findings are most useful as concrete inputs and the wrong output or crash they cause, each tied to the decision or
section it breaks.
