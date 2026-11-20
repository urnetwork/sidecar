# Sidecar: implementation review handoff

*2026-11-20, 13:40 (UTC−6), written while the draft's last tracks run. From the build to the peer reviewer.*

[HANDOFF.md](HANDOFF.md) handed the design to the implementation team. This document hands the implementation to
its reviewers. It summarizes:

- what was built and where it lives;
- how it was built and checked;
- what is known to be missing;
- where a reviewer's time is best spent.

It is a snapshot. The numbers below were true when it was written; the branches keep moving until the draft ends.

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
- **What "drafted" means.** It does not mean reviewed by a person. For each piece of work:
  1. An agent built the track from its brief.
  2. A second agent reviewed it independently and adversarially.
  3. The findings were fixed.
  4. The track landed through `track-land`, after its tests passed: the sidecar module, plain and under
     `sidecar_testhooks`, plus the packages it touched in other repos.

  Nobody has read the code line by line. Treat every claim in a commit message as the author's claim.
- **How much.** The plan has 923 tasks across 24 areas:

  | State | Tasks |
  |---|---|
  | Done | 18 |
  | Drafted | 895 |
  | Landed with an item still open | 6 |
  | Running | 3 |
  | Stuck | 0 |

  M0 to M3, M5 and M8 are complete. M4 is at 60 of 61, M6 at 103 of 105, M7 at 39 of 40, M9 at 57 of 58, and M10 at
  131 of 134. Five tasks are held for decisions deferred to Later: QD-1038 (2), QD-1032, QD-047 and owner decision 279.
- **What is still running.** 12 tracks remain across five lanes. Most are fixes that follow answered questions. The
  largest are `fault-clause-registry` (QD-1084's clause registry, 49 files) and `mcp-m7-01` (MCP-M7-01, MCP-M9-01 and
  MCP-M10-01). Section 10 covers what follows them.
- **Health.** The build's continuous check (`tip-check`, section 6) was green at sidecar `503269c2`. The `sidecar`
  branches were last pushed to origin at sidecar `1d70ee9d`. The local tip when this was written was `99de6ff9`. `main`
  is untouched in every repo, and nothing is deployed.
- **Decisions.**
  - Owner decisions run to 646.
  - The build's question ledger runs to QD-1149.
  - Since 2026-11-16 the owner's standing instruction has been to accept each question's recommended option. So most
    late QDs were answered that way, recorded, and turned into fix tracks.
  - [DESIGN-AMENDMENTS.md](DESIGN-AMENDMENTS.md) holds decisions that [DESIGN.md](DESIGN.md) does not have yet, and
    [DESIGN-DEFER.md](DESIGN-DEFER.md) holds what was put off.
  - A final design sweep folds QD-1115 onward into the design before the handoff.
- **Where to start.** Read section 7's first item, host composition: much of the system is built and tested but not
  yet wired into `ur daemon` or the apps. Then follow section 8's order.

## 2. Repos and branches

Each repo below has a `sidecar` branch. The counts are commits without merges since the branch left `main` (or the
fork's default branch), and the size of the diff.

| Repo | Commits | Diff | What is there |
|---|---:|---|---|
| sidecar | 2,949 | 6,529 files, +1.74M / −8.8k | The new module: the core, the `ur` CLI, MCP, the service engines, the test worlds and the design sources. The size includes vendored `third_party/` and generated protobuf code. |
| server | 844 | 1,454 files, +386k / −1.2k | The service blocks and their hosts, team and ACL state, mail, dns, abuse, quota, `sidecarctl`, the gate tool and the T3 tests (section 4). |
| sdk | 158 | 235 files, +86k / −12k | `sdk/sidecar.go` and the app-facing bindings (mail, directory, search, state events). |
| connect | 161 | 117 files, +40k / −12k | The default-off connect changes (the C-numbered list in §4.18), and the API spec `api/bringyour.yml`. |
| warp | 68 | 80 files, +25k / −0.9k | `services/sidecar-blocks/` fragments, the lb's `internal_routes`, warpctl. |
| minio (fork) | 44 | 91 files, +18k / −0.3k | The `urnetwork/minio` fork's changes for evs's storage. |
| xops | 52 | 108 files, +12.5k / −0.2k | Ansible plays: the edges play, the dbs play (PgBouncer entries, HBA rules, slot budget) and the Redis backup filter. |
| build | 40 | 88 files, +9.9k / −0.1k | Release Makefiles and the pending-tag guard. |
| mmm | 22 | 108 files, +8.9k | ur.io's `install.sh` and its OAuth consent page for `ur login`. |
| operator-core | 9 | 38 files, +4.5k | The host contract (owner decision 251): package `operator`'s `Env`, its global env (QD-1027), and the quota refusal and limits types. |
| config, sn, tests | 29, 12, 3 | small | Settings, the sn changes and test fixtures. |
| glog, userwireguard, proxy | 1 each | one line | The Go 1.27.4 line (QD-674). |

DESIGN.md is generated from `sidecar/design/source/`: its 23 section files, and the owner's record of decisions 1 to 646
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
- **Questions.** An agent that met a choice the design left open stopped and wrote a question, with options and a
  recommendation (`.stack/questions/`). Each answer has a QD number in `.stack/decisions/` (`LEDGER.json`,
  `RESOLUTIONS.md`), and is written back into its question file. Answers that needed code became fix tracks. Design
  text goes into DESIGN.md through design-records tracks.
- **The trail behind a line of code.**
  - Commit messages are long. They name the task (for example `EVS2-M10-31`) and the decisions (QD-n, owner decision
    n) they implement, so `git log -S` and `git blame` usually find the reason.
  - `.stack/state/drafted.txt` holds 995 entries, one per drafted task, each saying what landed and what was put off.
    729 of them name review-phase work.
  - `.stack/state/review-phase-work.md` holds the owner decisions that place work in the review phase, and the open
    items from each recent track's report.
  - `.stack/state/final-design-sweep.md` holds what the last sweep folds, the owner's steps before deploy, and the
    handoff's test notes.

  `.stack` is the build's local workspace, not a repo, so it is not on origin. Ask for a copy if you review from
  origin.
- **Commit rules.** Merge, never rebase. No AI attribution in any commit. Only the orchestrator pushes, at
  checkpoints, and only `sidecar` branches.

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
  `check/` under `sidecar_check`.
- server: run tests through the build's `.stack/server-test.sh <server checkout> <go test args>`. It keeps
  `server/test-env.sh`'s guards on.
- Gates: `sidecar-gate <gate> -list` lists a gate's rows. A full run needs the private stores and T3's layouts. M9's,
  M10's and the held gate's full runs have not been taken; only `-list` and direct package runs have.
- `tip-check` runs at every new sidecar tip. It runs `make check`, plus server's untagged vet and a set of named audits:
  the root package's, and evshost's routes against `bringyour.yml`. It also runs sdk's vet and root-package audits.

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

**1. Host composition.** This is the largest theme. Components that are built and tested at unit and T2 level have no
production host yet:

- No Sidecar builds an `SmtpSender` or runs an `SmtpOutboxRunner`. So `CheckSend` prices through `p/` records on every
  host.
- Nothing installs the search `IndexWriter`, builds `SearchRemoteServer` for `Daemon.ServeRemoteSearch`, or calls
  `ApplySearchDesignatedSettings`. Only mail binds `ConfigIndexerServicesOpener`.
- No search scope source exists, so production searches apply no `searchable_days` mask. QD-1138 says what it must
  pass.
- The record runs on `RecordAuthUnavailable`. Nothing builds `RecordEvsStreams` or `NewRecordComponent`, or calls
  `SetEraseIndex`, so format 2's record erasure and Team cost entries are off in a real daemon.
- Nothing calls `SaveAclTeamStart`.

To find more, search `drafted.txt` for "Nothing constructs", "no Sidecar builds", "nothing calls", "has no caller" and
"not wired".

**2. Owner decisions that put work in the review phase.**

- **QD-1028.** Move server-hosted sidecar code into `sidecar/{model,controller,work,handler}`. It runs as a barrier
  once the lanes drain.
- **QD-1035.** Remove presence-key attestation.
- **QD-1040.** MLS is set aside. Rework key formation onto KeyDelivery wraps, and keep the MLS code dark.
- **QD-706.** The settings sweep.
- **QD-641.** The storage-first engine work.
- **QD-1032.** The dark prefix rules stay off.
- **QD-1067 and QD-1068.**

**3. Gates that read missing or open.**

- M9's and M10's exits and the held gate list many rows as missing. Reasons include:
  - case-tiers with no registered builder (33 at M10's exit, 17 cases in the held gate);
  - FI-13, FI-14, FI-25 and FI-26 not bound;
  - schedules that name no invariant (FS-74, FS-75, FS-87, FS-88, FS-99, FS-107, FS-108, FS-111);
  - S6 missing from §22.7's registry;
  - owners' inline paths not calling `InlinePath` yet.
- The rows people, hardware or production owe are listed with the owner's steps.
- QD-1084's clause registry is still landing.

**4. Items that deserve a careful eye first.**

- **Held drop jobs.** This bug predates the draft's last fixes. A held job that resumes after its hold ends and then
  fails leaves its entries held with no record. Their dropped ids can then be read again.
- **`mail_strict`.** It can be set, but until connect's C20 DNSSEC validator lands, strict mode refuses every spliced
  session.
- **The shared edge bearer.** tlsedge, smtpedge and mxedge share one bearer class. A stolen one can mark a Team's MX row
  verified or failing.
- **PgBouncer.** Its HBA rules and two `min_pool_size` readings have not been checked against a running PgBouncer 1.26.
- **Completion ERASEs (QD-1137).**
  - A stray completion naming another erasure's key blocks that erasure's own completion.
  - On real evs, `IndexEraser` sends no completion yet, because `Retained` always answers incomplete.
- **Policy tests.** An activated route grant meets no `ip:` check. This is a candidate question.
- **MTA-STS.**
  - A verification change with no writer reaches the zone only at the network's next sign-in or payment.
  - The reconcile's post-commit hint takes a pooled connection while its caller holds one.

**5. Test debt.**

- Mutation sweeps beyond spot mutants, fuzzing, exhaustive FS schedules, T3 runs of many format-2 cases, and
  benchmarks.
- Known flaky behaviour:
  - `TestEvsMapperUploadsPartsAtOnce` can hang a run; a fix track is placed.
  - `sidecartest`'s `FakeClock.Advance` can set the clock back under two movers.

**6. Spec and doc drift.**

- `bringyour.yml` still has gaps:
  - evs push refusals with no body content;
  - 402 answers worded "with terms";
  - `test_spec.py`'s served set lacking 14 evs operations.
- `check-routes.sh` does not see routes a handler registers through `Routes()`.
- The design wording items are listed in the final design sweep.

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
- **The lb.** Fill in its allow-list site ranges, and rebuild its image and units.
- **Key files.** Draw smtpedge's X-UR-Ref key file before M9's platform fragment. Draw the abuse mailbox's keys.
- **The Redis backup filter.** Deploy it.
- **Postmaster tools.** Register them.
- **The CLI's spellings.** Supply the owner's `design/UI.md` for the CLI's final spellings.
- **What production and hardware owe.** Soaks, the T4 to T6 runs, and the people's sign-offs that the gates read as
  open.

## 10. What happens next

The lanes finish their last tracks. Then come, in order:

1. **The final design sweep.** It folds QD-1115 onward into DESIGN.md, DESIGN-DETAILS.md and RECORD.md. Its list is
   in the final design sweep file.
2. **A green tip-check.**
3. **The final push of the `sidecar` branches.**
4. **A pause for the owner's next-phase instructions:**
   - the review phase, which this document opens;
   - then the apps' UI;
   - QD-1028's layout move, which runs as a barrier once the lanes drain.

Findings are most useful as concrete inputs and the wrong output or crash they cause, each tied to the decision or
section it breaks.
