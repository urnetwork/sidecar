# Sidecar: integration test handoff

*2026-11-27, 18:05 (UTC−6). From the build to the developer who takes over integration testing.*

On 2026-11-27 the owner said: "I want to hand off integration tests to another developer. The work here will only be
implementation going forward, using opus 5.5 max." This document is that handoff. It covers four things:

- what is built, and where;
- how it is tested today;
- what integration testing is now yours, in the order the build suggests;
- how to work beside the build, which keeps landing code on the same branches.

[REVIEW-HANDOFF.md](REVIEW-HANDOFF.md) maps the code of DESIGN.md's milestones M0 to M10 and lists the review's gaps.
This document refers to it rather than repeating it.

## Contents

1. [The short version](#1-the-short-version)
2. [What is yours, and what the build keeps](#2-what-is-yours-and-what-the-build-keeps)
3. [Repos, branches and documents](#3-repos-branches-and-documents)
4. [Implementation state](#4-implementation-state)
5. [Testing as it stands](#5-testing-as-it-stands)
6. [The integration test plan](#6-the-integration-test-plan)
7. [Working beside the build](#7-working-beside-the-build)
8. [Rules that bind you](#8-rules-that-bind-you)
9. [Gates and owner decisions that bound the testing](#9-gates-and-owner-decisions-that-bound-the-testing)
- [Appendix A: the compute end-to-end tasks handed to you](#appendix-a-the-compute-end-to-end-tasks-handed-to-you)
- [Appendix B: tip-check's findings on 2026-11-27](#appendix-b-tip-checks-findings-on-2026-11-27)
- [Appendix C: failures that come from the host, not the code](#appendix-c-failures-that-come-from-the-host-not-the-code)

## 1. The short version

- **DESIGN.md, M0 to M10.** All of it is drafted (923 plan tasks), on the `sidecar` branch of every repo it touches.
  It was peer-reviewed on 2026-11-20, and the review's fixes were merged on 2026-11-21. REVIEW-HANDOFF.md is the map.
- **The end-to-end suite.** The suite in `server/sidecare2e` runs every server block in one process, with real
  `sidecar.Sidecar` clients against them (section 5.2). Its eight scenario cases passed together on 2026-11-23:
  - first on server `d02ee917d` and sidecar `f4398d17`;
  - then 24 of 24 at that day's tips, server `3c7b6ec65` and sidecar `44097a35`.

  About fifty fix tracks came from its findings. Nothing runs the suite regularly yet; the e2e plan's step 5, a
  nightly leg, was never built.
- **DESIGN-COMPUTE.md.** This covers secure inference, the gateway, the Harness, agents, enclaves, search and the
  compute balance. Its draft began on 2026-11-24 and is in progress:

  | Tracks | Count | Plan tasks |
  |---|---:|---:|
  | Landed | 50 | 124 |
  | Running | 7 | 15 |
  | Still to build | 80 | 173 |
  | Handed to you | 3, and part of 2 more | 6, and half of a seventh |
  | **Total** | **140** | **318** |

  The handed-off work is the compute plan's end-to-end tasks (section 2, Appendix A). At the current pace the draft
  finishes in early December.
- **DESIGN-UI.md.** The apps' and ur.io's UI is not started. It follows the compute draft.
- **Health.** `tip-check`, which reruns the module's whole check at each new sidecar tip (section 5.4):
  - Its last green was sidecar `09e31f43`, at 13:51 today. That round skipped two tests whose fixes have since landed.
  - A round with no skips is running.
  - Origin's `sidecar` branches were pushed at that green: sidecar `09e31f43`, sdk `afc23d37` and server `3e9c8b85`.
  - `main` is untouched in every repo, and nothing is deployed.
- **Decisions.**
  - Owner decisions run to 807, and the build's question ledger to QD-1455.
  - The design documents carry every decision through QD-1454, folded today by the seventeenth fold, `dr25-fold`:
    DESIGN.md, RECORD.md and DESIGN-COMPUTE-AMENDMENTS.md.
  - Compute's answers are filed in [DESIGN-COMPUTE-AMENDMENTS.md](DESIGN-COMPUTE-AMENDMENTS.md), since
    DESIGN-COMPUTE.md is the owner's to revise.
- **The date that matters.** The owner expects the sidecar product to merge in mid-December. TEE models, encrypted
  enclaves and web search are in the first release, so their gates are on the critical path (section 9).

## 2. What is yours, and what the build keeps

**Yours from today:**

- **The end-to-end suite and its harness.** `server/sidecare2e`'s World, hosts and helpers, its upkeep as the code
  under it moves, and new scenarios.
- **A regular e2e leg.** The e2e plan's step 5: a bounded subset nightly, the full suite on a slower beat, and the
  sidecar-related server packages' own tests (section 6.1).
- **The compute plan's end-to-end tasks.** The build no longer places these; Appendix A has their full plan entries:

  | Task | What it is |
  |---|---|
  | CTEST-M12-05 | The compute world on the local test stack, and the ledger end to end |
  | CTEST-M12-07 | Direct calls end to end |
  | CTEST-M13-05 | Claude Code's conformance, and the harnesses' hosted search |
  | CTEST-M13-06 | Web search end to end |
  | CTEST-M13-07 | The ur.io row: the page leg's suite under Node, and the browser suite in mmm |
  | CTEST-M14-03 | Enclaves end to end |
  | CTEST-M15-01 | The end-to-end half only; the build builds its fakes |
- **The gate runs nobody has taken.** M9's, M10's and the held gate's full runs through `sidecar-gate`; T4's device
  cells; T5's and T6's load and production-like runs.
- **The v1 gates' test campaigns** (section 9).

**The build keeps:**

- **Implementation.** The remaining DESIGN-COMPUTE.md tracks run on four lanes of Opus 5.5 max agents, then
  DESIGN-UI.md. Each feature track writes its own package tests (T2, and T3 where its plan task says), as before.
- **Compute's shared test seams**, in package `sidecar/sidecartest/computetest`:
  - landed: `ScriptedModel`, `FakeComputePolicy`, `FakeCalendarServer`, `FakeParallel` and `FakeBase`;
  - running: `Broker` and `FakeStores`;
  - to come: `FakeInferenceProvider`, `FakeWeb`, `FakeOauthIssuer`, `FakeTeeEvidence` and `FakeEnclaveProvider`;
  - also the T2 privacy guard over compute-1 to compute-11 (CTEST-M12-04), and the harness conformance runner with
    Codex against the gateway (CTEST-M12-03, landing now).

  Your scenarios build on these. Each fake fails a call it was not scripted for with a named error, never a default
  answer.
- **Fixes and design records.** Fix tracks for every tip-check red and for the product bugs your tests find, and the
  design-records folds that keep DESIGN.md current.

## 3. Repos, branches and documents

Every repo below has a `sidecar` branch. Work from origin's. These tips were on origin at 18:00 today; the date is
the tip commit's:

| Repo | origin/sidecar | Tip's date | What is there |
|---|---|---|---|
| sidecar | `09e31f43c` | 2026-11-27 | The module: the core, `ur`, MCP, the service engines, the test worlds and fakes, the design sources |
| server | `3e9c8b85f` | 2026-11-27 | The blocks' binaries and hosts, `sidecare2e`, `sidecart3`, the gate tool, `sidecarctl`, team, ACL, mail, dns and quota state |
| sdk | `afc23d37d` | 2026-11-27 | `sdk/sidecar*.go` and the app-facing bindings |
| connect | `09edd2128` | 2026-11-27 | The default-off connect changes and `api/bringyour.yml` |
| xops | `e82659706` | 2026-11-27 | The edges and dbs plays |
| warp | `225caae7a` | 2026-11-26 | `services/sidecar-blocks/` fragments and the lb's internal routes |
| build | `97b1bbe91` | 2026-11-26 | Release Makefiles and the pending-tag guard |
| minio (the `urnetwork/minio` fork) | `1e00ad81a` | 2026-11-24 | evs's storage |
| mmm, operator-core | `d36e5f538`, `a330f79c5` | 2026-11-24 | ur.io's pieces, and the host contract |

The build lands faster than it pushes. Expect origin to move about every three hours (section 7).

**Documents in the sidecar repo:**

| Document | What it holds |
|---|---|
| [DESIGN.md](DESIGN.md) | The product's design, generated from `design/source/`; §22 is the testing design (the tiers, the privacy harness, the conformance peers) |
| [DESIGN-AMENDMENTS.md](DESIGN-AMENDMENTS.md) | DESIGN.md decisions that are not yet in it |
| [DESIGN-COMPUTE.md](DESIGN-COMPUTE.md) | The compute extension; §18 is its testing table, and every CTEST task cites a row of it |
| [DESIGN-COMPUTE-AMENDMENTS.md](DESIGN-COMPUTE-AMENDMENTS.md) | The answers to compute's questions, by section, until the owner folds them in |
| [DESIGN-UI.md](DESIGN-UI.md) | The apps' and ur.io's UI, which comes after the compute draft |
| [REVIEW-HANDOFF.md](REVIEW-HANDOFF.md) | The implementation's map, the test tiers, and the review's gaps (its section 7) |
| [HANDOFF.md](HANDOFF.md) | The design's handoff to the implementation |
| [RECORD.md](RECORD.md), [metadata_list.yml](metadata_list.yml) | recURd's record format, and §2.8's list of every value a server sees, which `check/` holds the code to |
| [CODESTYLE.md](CODESTYLE.md) | Code conventions, including the test data rule (no secret, production hostname or real IP in a test) |

**The build's workspace, `.stack`, is not a repo.** It is not on origin. The plan (`.stack/plan/`), the question
ledger (`.stack/decisions/`), the track reports and the e2e plan (`.stack/state/e2e-plan.md`,
`.stack/briefs/e2e/CONVENTIONS.md`) live there. This document carries what you need of them. Ask the owner for a copy
of the rest.

## 4. Implementation state

### 4.1 DESIGN.md: M0 to M10

Every milestone is drafted. REVIEW-HANDOFF.md's section 1 gives the task counts, and its section 7 lists the open gaps
by area. Since it was written:

- The review fixes have merged.
- The e2e suite was built and passed (section 5.2), and about fifty fix tracks closed its findings.
- The design folds `dr14` to `dr25` brought DESIGN.md to owner decision 807.

Work the owner placed in a later review phase is still owed:

- QD-706's sweep of drafted constants into settings objects (QD-702);
- QD-1086's KEYS rework;
- QD-024's `design/UI.md` names for `ur`'s commands.

### 4.2 DESIGN-COMPUTE.md: the draft in progress

The compute plan has 24 areas. Each area's plan file names its tasks, files, needs and tests. This was the state at
18:00 today, counted by track; a track can hold a neighbouring area's task:

| Area | DESIGN-COMPUTE | What it is | Tracks landed of all | Tasks landed of all |
|---|---|---|---:|---:|
| Skeleton | §1, §3 | settings, wiring, placement, modules, wire numbers | 2 of 2 | 6 of 6 |
| CARCH | §1, §3, §17 | §17's abuse controls and legal process; the compute hold and refused regions | 1 of 1 | 2 of 2 |
| CTRUST | §2 | disclosures and acknowledgments, key custody, the IC-1 to IC-24 matrix | 3 of 3 | 5 of 5 |
| CACL | §16 | CanonicalAction version 5 and kinds 19-26, acl.proto's atoms, the models key, budgets, enforcement | 4 of 7 | 10 of 13 |
| CSRV | §14 | `computeservice`'s engine and host, migrations, routes, jobs, the search signer's block | 4 of 5 | 9 of 10 |
| CSURF | §15 | the sdk's compute accessors, the gomobile twins, the surface tables | 1 of 2 | 1 of 3 |
| CTEST | §18 | the shared fakes, the conformance runner, privacy, the end-to-end worlds | 2 of 10 | 4 of 20 (7 yours, CTEST-M15-01 in part) |
| PROV | §4 | the provider adapters, the reference provider, engy, SayGM and Chutes, the canary | 1 of 3 | 1 of 5 |
| ATTEST | §5 | the signed compute policy, freshness tickets, TDX, SEV-SNP and GPU verifiers, collateral | 2 of 6 | 3 of 11 |
| INFER | §6 | names and the catalog, the router, `ur-engine`, the direct and TEE paths, disputes | 5 of 9 | 13 of 21 |
| HARN | §7 | the Harness: events, tools, approvals and taint, agents, the renderer, attach | 3 of 12 | 11 of 26 |
| CTXH | §24 | context history: entries, the journal, resume and fork, the gateway's recording | 4 of 5 | 10 of 11 |
| SKILL | §20 | the recURd skill: agent repos, status, inboxes, delivery, the agent tools | 3 of 5 | 8 of 11 |
| GIT | §13 | the bundled git on EVS | 1 of 4 | 2 of 9 (3 running) |
| GW | §8 | the local gateway: listener, grants, Responses, Chat Completions and Messages | 2 of 5 | 5 of 11 (3 running) |
| BAL | §9 | the compute balance: ledger, holds, Stripe and the stores, limits, promotion codes, refunds | 7 of 10 | 20 of 26 |
| GAMMA | §10 | the treasury: `GammaChain`, mints and spends, reconciliation | 0 of 2 | 0 of 7 |
| ENC | §11 | enclaves: admission, the orchestrator, provisioning, egress, the indexer enclave | 1 of 10 | 2 of 31 |
| SSH | §12 | the bundled SSH client and server, login rules, receipts | 0 of 3 | 0 of 8 |
| SRCH | §21 | web search: the x402 client, `searchsigner`, the broker's admissions, the tool | 2 of 7 | 4 of 16 (2 running) |
| FETCH | §22 | web fetch: egress and address checks, the extractor, kind 23 | 0 of 4 | 0 of 7 |
| MAILCAL | §23 | mail and calendars for agents, kind 25, receipts and Undo | 0 of 6 | 0 of 13 |
| CONN | §25 | connected services: definitions, sign-in, the connection store, kind 26 | 0 of 7 | 0 of 12 (3 running) |
| LSTN | §26 | listeners: discovery, the listeners repo, the listener rule, the live ask | 1 of 6 | 4 of 17 (1 running) |
| SAFE | §27 | automatic approvals: the tokenizer and classifier, scores, the verdict entry, modes | 1 of 6 | 4 of 17 |

What already runs end to end in-process is the device's side of inference, the gateway's first routes, the balance's
ledger and the compute block's engine. Your first compute scenario, CTEST-M12-05, needs CSRV-M12-03 and CSRV-M12-04
(both landed), plus CTEST-M12-02 and CTEST-M12-04 (section 6.2).

**Running at 18:00.** Each lane runs its tracks in order:

| Lane | Tracks |
|---|---|
| core | `support-log-start-after-close` (a fix), `conn-m13-01`, `conn-m13-02` |
| data | `fwd-compile-wanted-stall` (a fix; Appendix B), `git-m13-03` |
| edge | `srch-m13-07`, `gw-m12-06`, `lstn-m13-08` |
| ops | `ctest-m12-01`, `x-image-vuln-bump` (a dependency bump), `sdk-license-check-replaced-texts` (a fix) |

### 4.3 DESIGN-UI.md

Nothing of the UI phase has started. Two things hold meanwhile:

- **The sdk surfaces.** The owner asked that the sdk be shaped as the common view controllers the apps' screens bind.
  So the compute tracks that touch an sdk surface give it each screen's fields, a listener and its actions, and build
  no screen.
- **DESIGN-UI.md's changes to DESIGN.md are held** until the UI phase: plans and prices, Team billing (seats on
  GitHub's model since the owner's v1 scope update), categories, mail tools, RBAC roles and role address ranges.

So do not expect UI behavior from the apps yet.

## 5. Testing as it stands

### 5.1 Tiers

These are DESIGN.md §22's tiers, with DESIGN-COMPUTE §18 for compute:

| Tier | What it is | Where | State |
|---|---|---|---|
| T2 | In-process worlds over fakes | `sidecar/sidecartest` (worlds, fakes, `fault/`'s FS schedules and FI invariants, gate sweeps), `sidecartest/computetest` | Most of the evidence |
| T3 | The private local stack: Postgres, Redis and MinIO file clusters | `server/sidecart3`, the `*_t3_test.go` files, `sidecar-t3.sh` | Part of the evidence |
| e2e | Every block in one process, with real sidecar clients, on T3's stores | `server/sidecare2e` | Eight cases; not run regularly |
| T4 | Physical device cells | none | Not run |
| T5, T6 | Load, and production-like runs | none | Not run |

### 5.2 The end-to-end suite: `server/sidecare2e`

**Its conventions** come from the build's e2e conventions, modeled on `server/connect` and `server/proxy`:

- **In-process.** Every server runs in the test process, built through its exported constructor and served on
  OS-assigned ports (`127.0.0.1:0`, or `server.ReserveTestListenPorts`). There are no subprocesses and no fixed ports.
- **Stores.** `server.DefaultTestEnv().Run` gives each test a fresh Postgres database, a leased Redis database and the
  migrations. Its rerun count is set to 0, so that a flake shows. File clusters run on the localstack MinIO, with one
  bucket set per world.
- **Clients.** The clients are real `sidecar.Sidecar` cores: `NewSidecarInstance` with the memory backend, `Unlock`,
  then `NewSidecar` with a `SidecarApiPlatform`. They enroll through the in-process api.
  - `sidecart3`'s `StartT3Sidecar` and `T3World` are the starting points.
  - The sdk refuses a non-https api URL, and `ur daemon` is `package main`, so neither is a client here.
- **Credentials.** Credentials never come from vault. Each block's `HostDeps` carries what its main would read, and
  the harness generates throwaway keys.
- **Concurrency.**
  - Many clients send bursts, one goroutine per burst, with random pauses.
  - Chaos stops and restarts hosts and residents mid-run.
  - Assertions are strict: order where the design promises it, exactly-once where it promises that, and exact ledger
    reconciliation (usage, budget, quota) at the end.
  - Each phase has a timeout and a progress dump on a stall.
  - Each case is bounded, 10 minutes by default.
- **Knobs.** Every knob is a settings field with its default (QD-702), never a constant.
- **Server state.** It is reached through the hosts, the api routes and model's `Testing_` helpers, gathered in one
  harness file. QD-1028's later layout move will take sidecar's code out of server/model, controller, api/handlers
  and taskworker.

**How to run it.**

- Every file carries the build tag `sidecar_e2e`, so ordinary runs skip it. Files also carry `sidecar_pending` (the
  pending migration groups) and `sidecar_localstack` (MinIO) where they need them.
- The build runs it through a wrapper that changes to the server checkout, sources `server/test-env.sh` (its
  attestation and dial guards stay on) and runs `go test` with `GOFLAGS=-trimpath`:

  ```sh
  cd server && source ./test-env.sh && GOFLAGS=-trimpath go test -count=1 \
    -tags 'sidecar_e2e sidecar_pending sidecar_localstack' -timeout 60m -run '<tests>' ./sidecare2e
  ```
- The build points test-env.sh at a private portable stack: Postgres on 127.0.0.1:55432 and Redis on 127.0.0.1:56379.
  It sets these:
  - `WARP_TEST_ENV_USE_PORTABLE_RESOURCES=1`;
  - `WARP_TEST_ENV_ALLOW_UNMANAGED_PORTABLE_SERVICES=1`;
  - `WARP_TEST_ENV_PORTABLE_ROOT` to its portable root;
  - `WARP_TEST_ENV_PORTABLE_POSTGRES_AUTHORITY` and `WARP_TEST_ENV_PORTABLE_REDIS_AUTHORITY`;
  - `BRINGYOUR_POSTGRES_HOSTNAME` and `BRINGYOUR_REDIS_HOSTNAME` to 127.0.0.1.

  Use your own private stack on ports like these, never the ports section 8 forbids.

**The cases:**

| Case | Main tests | What it proves |
|---|---|---|
| World and hosts | `TestE2eEveryHostRunsInOneProcessAndStopsClean`, `TestE2eWorldSmoke`, `TestE2eWorldSmokeUnderTheContractGate`, `TestE2eWorldRealKeys`, `TestE2eWorldRestartsEveryBlockOnItsStores`, `TestE2eWorldMail`, `TestE2eWorldTeamNetwork`, each host's `...AnswersItsStatusOnAnOsPort`, `TestE2eHostsVerifyServiceTokensUnderTheirInjectedKeys` | All ten blocks in one process on real keys, a smoke across every service, and restarts on their own stores |
| evs | `TestE2eEvsConcurrency` | Many writers on one repo and ref (CAS, file mode, exact head), reads during pushes, drops and holds, erasure under writers, an evs host restart mid-push |
| gkm | `TestE2eGkmConcurrency`, `...Reform`, `...SecondDevice`, `...ExactRaceHoldsEachRotatorToWhatItRacedFor` | Membership churn and rotations across devices, re-form under contention, recovery, one generation at the end |
| blogger (the owner's case) | `TestE2eBlogger`, `TestE2eBloggerChangeAfterTheReadersOwnRead` | Writers' webservers behind one tlsedge name through sockets' fair scheduler, articles on evs, caches cleared on evs's change hint, readers through tlsedge, chaos |
| it bridge (the owner's case) | `TestE2eItBridge`, `...Static`, `...RouteGrants`, `...Shares`, `...LinksPastSidecarClients` | Subnets joining and leaving, port forwards set up and removed, gVisor clients' IP and port forwarding reaching the right destinations (§17) |
| mail | `TestE2eMailConcurrency`, `TestE2eMailReportSeal`, `TestE2eMailInternetSenderVerdicts` | smtpedge out and mxedge in, many senders and mailboxes, an outbox crash and restart, exactly-once per effect key, no cross-mailbox delivery |
| dns and certs | `TestE2eDnsCertsConcurrency` | Custom domains, record updates through dns's api with dnsedge serving, challenges with the real certs worker and an in-process Pebble, monotonic serials |
| control plane | `TestE2eControlPlaneConcurrency`, `...Chaos`, `...ColdGate`, `...Quota` | Many devices enrolling, config and ACL saves racing (exact head), team churn, quota and budget under concurrent use |
| churn load | `TestE2eChurnLoad` | Mixed workers over rounds across every service with chaos, then exact ledger reconciliation |
| grant lag | `TestE2eGrantLag`, `TestE2eGrantLagSourceHandsOutEachEntryOnceDue` | QD-1226's 5 s window between a grant and a device acting on it |

**What it does not cover yet:**

- None of DESIGN-COMPUTE: there is no compute block, gateway, Harness or broker scenario in it.
- No app, sdk or `ur daemon` client.
- Nothing past one host process.
- Some e2e findings left open, in REVIEW-HANDOFF.md's section 7 and section 6.4 below.

### 5.3 The module's own checks

- **sidecar, `make check`.** It runs every module plain and under `sidecar_testhooks`: the root, `cli`,
  `smtpproof` and `mlsinterop`. Then the leak leg, then `check/` under `sidecar_check`. Its notes report the open
  schema-guard rows, the fuzz seeds run, and the conformance peers still open (71 in
  `testdata/conformance/peers.yml`). The build sets `TEST_TIMEOUT=120m`: on its loaded host the fault package's run
  takes 15 to 30 minutes.
- **The gate tool.** `server/local/sidecar-gate`'s `gates.yml` is generated from sidecartest's gate sweeps.
  `sidecar-gate <gate> -list` lists a gate's rows. A full run needs the private stores and T3's layouts.
- **T3.** These are `server/sidecart3`, the `*_t3_test.go` files and `sidecar-t3.sh`, with the `sidecar_localstack`
  tag for MinIO.
- **Build tags.** REVIEW-HANDOFF.md's section 3 lists them: `sidecar_testhooks`, `sidecar_check`, `sidecar_leaktest`,
  `sidecar_localstack`, `sidecar_http` (the js/wasm page Worker), `ios_extension` (the forwarding leg) and
  `ur_engine` (the inference helper).

### 5.4 tip-check

The build reruns this at each new sidecar tip, one round at a time, about 1.5 to 2.5 hours a round on its host:

- sidecar's `make check`, as above;
- server: untagged `go vet ./...`, the root package's named audits, and evshost's routes against connect's
  `bringyour.yml`;
- sdk: untagged `go vet ./...`, and the root package's tests untagged and under `sidecar_testhooks`;
- minio: the shipped leg's `govulncheck` rule (QD-1228).

It does not run `sidecare2e`, the T3 tests, or the sidecar-related server packages' own tests. That gap is why the e2e
plan's step 5 exists (section 6.1).

Appendix B lists today's reds and their causes. Several share a lesson: the build's host runs four or five agents
beside tip-check, at load averages of 30 to 110. Tests with real-time bounds failed only under that load, and a few
real races showed only there.

## 6. The integration test plan

### 6.1 The order the build suggests

1. **Make the suite run regularly.** This is the e2e plan's step 5:
   - a bounded subset of `sidecare2e` nightly, and the full suite on a slower beat;
   - the sidecar-related server packages' own tests on the same leg: `controller`, `taskworker`, `api` and the
     hosts (`evshost`, `dnshost`, `mxedgehost`, `quotahost`, `sidecarhost`, `socketshost`, `tlsedgehost`,
     `smtpedgehost`).

   Those packages' tests are not run anywhere regularly. Controller's
   `TestTlsCertsInstallFollowsSidecarYmlAndTheConfigMount` went red unseen on 2026-11-21 for that reason.
2. **Rerun the eight cases at today's tips.** The last full pass was 2026-11-23, and the compute draft has since
   changed code under them:
   - record kinds 54, 55 and 57;
   - the ACL's CanonicalAction version 5 and kinds 19 to 26;
   - the agents' inboxes;
   - the support log;
   - the clock sweeps across every component's waits (QD-1425).

   Expect findings.
3. **The compute world, CTEST-M12-05.** Build it once CTEST-M12-02 (`FakeStores`, landing now) and CTEST-M12-04 (the
   privacy guard) land. It is the world every later compute scenario runs in: the compute block started in
   process through `computehost.RunHost`, api's compute routes, the devices' compute clients and `FakeStores`.
   CTEST-M12-04 is next in the build's queue but not yet placed.
   Then the rest of Appendix A, in this order:
   1. direct calls (CTEST-M12-07);
   2. web search (CTEST-M13-06), the payment-path test of G-SRCH-parallel;
   3. Claude Code's conformance (CTEST-M13-05);
   4. enclaves (CTEST-M14-03), for G-PROV-hippius;
   5. the TEE path's end to end (CTEST-M15-01);
   6. ur.io's page-leg suite under Node and the browser suite in mmm (CTEST-M13-07).

   Each depends on its feature areas landing first; section 4.2 shows where they stand.
4. **The v1 gates' campaigns** (section 9). Raise early with the owner any gate that cannot pass by the merge.
5. **The full gate runs never taken.** M9, M10 and the held gate, through `sidecar-gate` on the private stores and
   T3's layouts.
6. **T4, T5 and T6.** Device cells (phones and desktops, the apps' VPN extension), load, and production-like runs.
   Nothing has run at these tiers.

### 6.2 Compute scenarios beyond CTEST's entries

CTEST's entries cover §18's rows. These concurrency cases, in the style of `sidecare2e`, are the build's suggestions
on top of them:

- **The gateway under many harness sessions.** Codex and Claude Code attach at once, with grants issued and revoked
  mid-stream and hour-long tokens expiring. Check retries under one Idempotency-Key, and that each call is recorded
  exactly once in context history.
- **The broker's admissions under bursts.** Many networks' devices buy, spend and refund at once while Redis is lost
  and restarted. The ledger must reconcile exactly: holds settle once and no credit is spent twice. CTEST-M12-05's
  `TestComputeLedgerConcurrencyWithRedisLoss` is the start.
- **Agents' inboxes and threads under concurrent writers.** The Harness's agents, the person's view and MCP sessions
  all write. The tests are taint, which withholds an untrusted writer's versions from a model; the thread limits; and
  the idle close of a watch.
- **Search's signer under concurrent sign requests.** The payee seal binds network, asset and amount (QD-1453). The
  nonce settles once, and the members' charge check (SRCH-M13-12) disputes a surplus.
- **Enclave churn.** Enclaves are created, attached over SSH and destroyed while their sponsor's device restarts.
  Check that no egress outlives its grant.
- **Listeners and the live ask** across devices joining and leaving a network (LSTN).
- **The approval path under load.** The automatic-approval classifier (SAFE) and a person's approvals race on one
  action, which must be decided once.

### 6.3 Each feature's own tests are not integration tests

A feature track writes T2 tests, and T3 tests where its plan task names them. Those prove one area against fakes.
They do not prove the services together with real clients, which is your remit. Where a scenario needs a seam a
feature does not expose, ask for it (section 7): the build adds it as a fix track, and you leave the product code
alone.

### 6.4 Items the draft left for integration or review

Each item below is from a track's report, with its evidence there:

- **mDNS service discovery** (owner decision 778). Three things are owed: a packet capture proving `LocalOnly`
  records never reach a LAN; an end-to-end world over the real subprotocol; and fuzzing of the mDNS wire parser, the
  DNS-SD answers, the translator and the watch's decoding. The owner also asked to run its discovery on real systems.
- **File clusters at their cap.** A write that ends unsent inside the cap reports `BlobUnknownError`, so callers such
  as `PutImmutable` read the key back through the same saturated queue. Fixing that needs a change to the blob error
  contract.
- **connect's restart latency.** p99 under heavy CPU contention is mixed (better at 32 copies and under -race, worse
  at 8 copies under load). One untraced 5 s no-answer appeared in 25,599 runs of an intermediate build.
- **The balance's crash recovery** (bal-m12-03). A kept row whose drop a crash interrupted is not dropped again, so a
  search's unsettled charge counts twice until a rebuild.
- **The forwarder's compile wake.** This is `fwd-compile-wanted-stall`, which is running. A host's forwarder held
  state at version 7 with a compile wanted, no waiter and no alarm, once in 112 tip-check rounds (Appendix B). If the
  track cannot reproduce it on T2, an e2e reproduction would settle it.
- **sdk's order-dependent tests.** `TestDeviceLocalCloseAndWaitJoinsCurrentMuxPump` and
  `TestExtenderStatusLastErrorNamesNoAddress` fail only beside the rest of their package.
- **REVIEW-HANDOFF.md's section 7.** Every item there still open.

## 7. Working beside the build

- **The build lands continuously.** Four lanes land tracks on the `sidecar` branches day and night. Each track
  merges the latest sidecar first and passes its landcheck. The build pushes origin's `sidecar` branches at
  checkpoints, about every three hours, and only at a tip-check green.
  - Its push tool refuses while origin holds commits it has not merged, so it never overwrites anyone.
  - Never force-push a `sidecar` branch.
- **Your own branch.** The build suggests a per-repo `sidecar-integration` branch from origin's `sidecar`, with
  `sidecar` merged into it often: merge, never rebase.
  - When you want your tests on `sidecar`, ask the owner. The build merges your branch under its landing lock, runs
    check's rules, and pushes at the next green.
  - If the owner would rather you push to `sidecar` directly, tell the build first. Its next push will then wait for
    a green that includes your commits.
- **Your files.** Your tests live where the build does not edit:
  - `server/sidecare2e`, which is yours now, with CTEST's `compute_*_test.go` files there;
  - any new e2e package you start.

  The build's tracks add tests only inside feature packages. If your test needs product code to change, do not
  change it yourself. Report it.
- **Findings.** A test that fails because the code is wrong stays failing. Never weaken an assertion to pass it.
  Send the owner the failing test, its seed or trace, and the tips it ran at. The owner hands it to the build, which
  fixes it as a fix track, merges the fix, and tells you the commit.
- **Design questions.** The build records each design choice as a question with options and a recommendation. The
  owner's standing instruction is to accept the recommended option, and the answer is recorded as a QD number. When
  your test needs a design call, raise it with the owner.
- **Commit style.** These are the repos' conventions:
  - long messages that name the task or decision they serve (for example `CTEST-M12-05`, `QD-1453`, owner decision
    789);
  - one author;
  - no AI attribution in a commit message;
  - merge, never rebase.

## 8. Rules that bind you

These bound the build and the review, and they bind integration testing too:

- **No production, ever.**
  - Never dial loopback ports 5432, 6432 or 6379 to 6427: those can be production data tunnels (see
    `server/test-env.sh`).
  - Never run `xops/bin/by-*` scripts, `warpctl` deploys, or `bringyourctl db migrate` against anything but your
    private test stack.
  - Change nothing on a real host.
- **No secrets.**
  - Never read, print or copy vault values. Credentials in tests are generated throwaway keys.
  - Put no secret, production hostname or real IP in code, tests or fixtures (CODESTYLE.md's test data rule).
- **Guards stay on.** Do not bypass `server/test-env.sh`'s attestation or dial guards, do not set
  `URNETWORK_TEST_REAL_VAULT`, and do not use `--no-verify`.
- **Never run the whole-suite scripts.** `server/test.sh`, `connect/test.sh` and `sdk/test.sh` take the shared
  `tests/network-intensive-suite-lock.sh`, which another team's campaign may hold. Run direct `go test` on the
  packages you mean.
- **Own sibling worktrees.** Never run `sidecart3`, `sidecare2e` or the fault suites through a symlinked sibling
  checkout. sidecartest/fault writes a failing seed's trace into `testdata/fault/seeds` of the sidecar checkout it
  runs in, which once dirtied a shared checkout with 401 files.
- **Leave others' things alone.** The Docker containers `urnetwork-local-pg` and `urnetwork-local-redis`, and anything
  started from `~/urnetwork`, belong to someone else.
- **Leave no process behind.** Stop every server, burner and test binary you start.

## 9. Gates and owner decisions that bound the testing

**The v1 scope (owner, 2026-11-26 and 27).** TEE models, encrypted enclaves and web search are in the first release.
Their gates move onto the critical path, and none goes away:

- **G-SRCH-parallel.** Three parts:
  - the payment-path test (CTEST-M13-06);
  - the external review of `searchsigner`, which should confirm QD-1453's binding of the sealed payee to network,
    asset and amount;
  - counsel's read on payee screening (DESIGN-COMPUTE §21.11).

  Until it passes, the signed policy carries no search line and the Harness leaves `web_search` out of its tools, so
  no app shows search.
- **G-PROV-hippius and its audit** (EPC-1 to EPC-9), for users' enclaves and for Burner's indexer enclave.
  CTEST-M14-03 is its end-to-end evidence.
- **A TEE provider ready at launch.** CO-32 drops any provider that does not accept gamma at launch, so TEE models
  need a provider that does, or a revision of CO-32. That decision is the owner's, and it is still open.
- **Credits on sale in v1.** Q-BAL-13 sells credits once something can spend them, and TEE models and search now can.
  CTEST-M12-05's purchase, promotion and refund scenarios are the balance's evidence.

**Other owner items that touch testing:**

- Counsel confirms the broker's refused regions (QD-1439) before M12's exit.
- There is no `RELEASE-KEY.pub` yet, so M11's exit waits on the release-key ceremony.
- `server/controller/gamma_chain.go` exists only on server's `main`. The owner has yet to say whether it comes to
  `sidecar` by a merge or is rebuilt for GAMMA's tracks.
- The owner's disclosure review covers QD-1440's generic wording of `connect:custom`.

If a gate cannot pass by the merge, raise it with the owner early. Either the date moves or the feature does.

## Appendix A: the compute end-to-end tasks handed to you

These are the build's plan entries, word for word from `.stack/plan/CTEST.md` as of 2026-11-27:

- **Paths** start at the workspace root, the directory holding every repo's checkout.
- **"Needs"** names tasks of the compute plan. Section 4.2 says which areas have landed, and the owner or the build
  can say whether a given task has.
- **"Proposed"** names are the plan's suggestions, not code that exists.
- **CTEST-M15-01**'s fakes stay with the build. Its end-to-end half is yours.
- **CTEST-M13-04 (`FakeOauthIssuer`)** stays with the build. Only CTEST-M13-05 is yours.

### CTEST-M12-05: The compute world on the local test stack, and the ledger end to end
- Milestone: M12
- Part: a
- Repos: server
- Size: L
- Spec: C§18, C§14.8, C§3.4
- Needs: CSRV-M12-03; CSRV-M12-04; CTEST-M12-02; CTEST-M12-04; existing: `NewWorld` (server/sidecare2e/world_test.go); soft: BAL C§9.5: purchases and their credits; soft: BAL C§9.11: promotion codes; soft: BAL C§9.12: self-serve refunds; soft: BAL C§9.13: the spend view; soft: CACL C§16.3: kind 21
- Provides: `computeWorld` (proposed); `newComputeWorld` (proposed); the ledger's end-to-end scenarios; `TestComputeOperationRowWritesPerCall` (proposed)
- Files: server/sidecare2e/compute_world_test.go, server/sidecare2e/compute_ledger_test.go, server/sidecare2e/compute_ledger_concurrency_test.go, server/sidecare2e/compute_privacy_test.go
- Build: §18's ledger and spend view rows end to end, and the world every later compute scenario runs in, on the local test stack (tags sidecar_e2e, sidecar_pending and sidecar_localstack): the World with the compute block started in process through computehost.RunHost on throwaway credentials, its gate open to the world's networks, api's compute routes mounted, the devices' compute clients pointed at it by the host list, and FakeStores for the markets, all in compute_world_test.go without editing world_test.go or hosts_test.go. Scenarios: a pack bought by Stripe Checkout, and by a store report racing its notification, credited once to the network its account token names; a promotion code redeemed once and its refusals (a second in the network, one within 30 days, past the day's load limit, by an agent, by a tagged sidecar), lapsing at 30 days; a self-serve refund by an Owner and its refusals; a budget raise filed as kind 21 on one device, approved on another, sent under its Idempotency-Key and retried, stored once; the spend view's totals against the charges a test service books through BAL's seam, a member's view holding only theirs; concurrency: devices of several networks buying, redeeming and raising at once while the settle loop runs, Redis dropped and the block restarted mid-run, every balance, lot draw and total equal to an uninterrupted run's (R2-07); §14.8's write count, four operation-row writes a call; and T3's privacy scan over the block's tables, Redis and logs with CTEST-M12-04's canaries. Traps: the blocks share one Redis and one Postgres as production's do; every scenario runs on the world's clocks and barriers, never a sleep; a scenario whose service has not landed is not written yet, never faked.
- Tests: TestComputeWorldStartsTheComputeBlock; TestComputePurchaseCreditsOnce; TestComputePromoRedemptionRules; TestComputeRefundRules; TestComputeBudgetRaiseStoredOnce; TestComputeSpendViewMatchesCharges; TestComputeLedgerConcurrencyWithRedisLoss; TestComputeOperationRowWritesPerCall; TestComputePrivacyOnTheLocalStack.

### CTEST-M12-07: Direct calls end to end
- Milestone: M12
- Part: b
- Repos: server
- Size: L
- Spec: C§18
- Needs: CTEST-M12-05; CTEST-M12-06; soft: INFER C§6.6: the direct path; soft: BAL C§9.7: holds, settlement and budgets as caps; soft: PROV C§4.6: the engy adapter; soft: CTRUST C§2.8: the `none` providers' disclosures; question compute-plan-adapters-before-commitment
- Provides: the direct path's end-to-end scenarios; `TestComputeBudgetsAsCapsUnderParallelCalls` (proposed)
- Files: server/sidecare2e/compute_world_direct_test.go, server/sidecare2e/compute_direct_test.go, server/sidecare2e/compute_direct_concurrency_test.go
- Build: §18's names-and-direct-path and ledger rows across the device, the broker and a provider, in the compute world with FakeInferenceProvider standing for engy under the test policy: a call to an `engy-*` model waits for the person's acknowledgment of engy's disclosure, then holds the declared model's worst case, is signed, served and settled from its receipt or its lookup, its hash dropped at settlement and in no log; the lookup's three states (unknown releasing the hold at no charge a minute after the window, in progress keeping it, finished settling it); a pending hold while the lookup fails, no new call signed to that provider, released at 24 hours on the world's clock; a served model that differs charged and flagged, a second mismatch refusing the network's direct calls; budgets as caps under parallel calls (R2-10): independent agent, device and member caps against a costlier receipt, no room spent twice, no one charged past a cap, the excess absorbed and shown; Codex reaching the model through the gateway; the canary job's known counts matched against the provider's usage. Concurrency: devices of several networks calling at once while settlement runs and the block restarts. Traps: the direct path and engy's adapter wait on G-PROV-engy (question compute-plan-adapters-before-commitment), so this runs on the fake under the test policy only.
- Tests: TestComputeDirectCallAcknowledgedHeldSignedSettled; TestComputeDirectLookupStates; TestComputeDirectPendingWhileTheLookupFails; TestComputeDirectMismatchFlagged; TestComputeBudgetsAsCapsUnderParallelCalls; TestComputeDirectConcurrencyWithARestart.

### CTEST-M13-05: Claude Code's conformance and the harnesses' hosted search
- Milestone: M13
- Part: b
- Repos: sidecar
- Size: M
- Spec: C§18, R-CCTX-10
- Needs: CTEST-M12-03; GW C§8.4: the Messages endpoint and count_tokens; soft: GW C§8.8: the settings `ur install-harness --gateway` writes; soft: SRCH C§21.7: the gateway's refusal of hosted search; soft: SRCH C§21.6: MCP's `web_search`
- Provides: Claude Code's transcripts; `conformance.ClaudeCode` (proposed); `TestHostedSearchIsOffInBothHarnesses` (proposed)
- Files: sidecar/sidecartest/conformance/claude.go, sidecar/sidecartest/conformance/claude_conformance_test.go, sidecar/sidecartest/conformance/hosted_search_test.go, sidecar/sidecartest/conformance/testdata/claude/
- Build: §18's gateway row for Claude Code and web search's per-release row: Claude Code's Messages transcripts under testdata/claude/<version>/ (`POST /v1/messages?beta=true`, SSE through `message_delta` and `message_stop`, `ping` during pauses, no empty thinking blocks, the fields it sends for unknown model ids accepted and ignored, `count_tokens`, WebSearch's side request with `web_search_20250305` answered `unavailable`), replayed as Codex's are, with its live mode (`ur claude`); and for both harnesses, the settings `ur install-harness --gateway` writes (Codex's `web_search = "disabled"`, Claude Code's WebSearch deny rule), the gateway dropping Codex's hosted search tool, and MCP's `web_search` reached from each harness's MCP session end to end, its bound run tainted. Traps: Anthropic does not support routing Claude Code to other models, so this suite is the compatibility claim (§8.3) and runs at each release.
- Tests: TestConformanceReplaysClaudeCode; TestHostedSearchIsOffInBothHarnesses; TestMcpWebSearchTaintsTheBoundRun.

### CTEST-M13-06: Web search end to end
- Milestone: M13
- Part: b
- Repos: server
- Size: L
- Spec: C§18
- Needs: CTEST-M12-05; CTEST-M13-03; CSRV-M13-01; soft: SRCH C§21.5: the search's payment; soft: BAL C§9.7: holds and charges; question compute-plan-adapters-before-commitment
- Provides: the web search end-to-end scenarios; `TestComputeSearchTwoAttemptsOneMinute` (proposed); `TestComputeSearchLostMapsAroundMidnight` (proposed)
- Files: server/sidecare2e/compute_world_search_test.go, server/sidecare2e/compute_search_test.go, server/sidecare2e/compute_search_chaos_test.go
- Build: §18's web search row across the device, the broker, the signer, Parallel and Base, in the compute world with the searchsigner block (CSRV-M13-01) in process on its own Redis and database, FakeParallel and FakeBase: a first search waits for `search:parallel`, then a 402, an admission within the clause, the ceiling, budgets, the daily and search caps and the rate, the signer's screen and its signature for the device's own nonce, the paid retry, settlement on the finalized head and one charge; a retried request id and attempt getting the same authorization; attempts 2 and 1 settled in reverse order in one minute, both reports repeated and attempt 3 lapsed: exactly two charges, in that minute's day and the lifetime totals (R2-08); synthetic transfers finalized around UTC midnight while the broker's and the signer's ticket maps are lost in turn and the notifications replayed: each settled authorization counted once, only attributed ones on statements, the day balanced (R2-09); a listed payee refused and paged; an out-of-band settlement kept as a sanctions record; the two sources disagreeing and pausing signing; per-search rows present at 71 h 54 min and gone at 72 h on the world's clock; outcome counts reaching the broker only as hourly counts across networks; no query byte in any broker log or metric (the privacy scan). Concurrency: devices searching at once against the global limiter. Traps: the signer is built only after G-SRCH-parallel's load test (question compute-plan-adapters-before-commitment), so this runs on fakes only.
- Tests: TestComputeSearchEndToEnd; TestComputeSearchRetryGetsTheSameAuthorization; TestComputeSearchTwoAttemptsOneMinute; TestComputeSearchLostMapsAroundMidnight; TestComputeSearchSanctionsPaths; TestComputeSearchRowsGoneAt72Hours; TestComputeSearchConcurrency.

### CTEST-M13-07: §18's ur.io row: the page leg's suite under Node, and the browser suite in mmm
- Milestone: M13
- Part: a
- Repos: sidecar, mmm
- Size: M
- Spec: C§18
- Needs: HARN-M13-04; CTXH-M13-02; INFER-M13-02; SAFE-M13-16; FETCH-M13-05; MAILCAL-M13-13; external: DESIGN.md's fold of CO-47 to CO-49 (COMPUTE-AMENDMENTS.md's CA-98 to CA-105: §18.8's admission and key origin, §18.4's browser column, C4, C17 and §18.10's page Worker build), which compute-lanes.json's after lists name as `designmd-fold-co47-to-co49`; question compute-plan-web-engine-files
- Provides: `computetest.PageWorld` (proposed: the page leg's end-to-end world); mmm's ur.io browser suite (proposed)
- Files: sidecar/sidecartest/computetest/page_world.go, sidecar/sidecartest/computetest/page_world_test.go, mmm/sidecar.ur.io/test/playwright/urio.spec.mjs
- Build: §18's ur.io row (CO-47, CO-48, CO-49). Without a browser, on the page leg under Node with fakes (`computetest.PageWorld`: a fake carrier for C4, computetest.Broker, a fake api model route and a fake engine module): Gemma 4 E2B downloads from the api with progress and resumes at the first missing chunk after a dropped connection and after a reload, an altered chunk fails its check and is fetched again, nothing opened before every chunk verifies; a run in ur.io's Harness writes a file, searches and fetches over C4 and asks for an approval the person grants on the page, the run in EVS and continued on a desktop; the classifier gating until its bench passes. In a browser, mmm's Playwright suite in Chromium where this machine has it: the engine Worker's CSP with no `securitypolicyviolation`, the probe's reason without WebGPU, the `ur-models` bucket evicted leaving the page Worker's state, two tabs sharing one engine Worker and a second network's waiting. On Chrome and Edge with WebGPU, Safari 26 and 27, Firefox, iOS and Android browsers and Lockdown Mode, with the engines' files installed: by hand, External (compute-plan-web-engine-files). Traps: every case is deterministic, barriers and fake clocks, never a sleep.
- Tests: The row's cases as listed, each a top-level test; the browser cases tagged for the hand runs.

### CTEST-M14-03: Enclaves end to end
- Milestone: M14
- Repos: server
- Size: L
- Spec: C§18
- Needs: CTEST-M12-05; CTEST-M14-02; soft: ENC C§11.6: the lifecycle and its timeouts; soft: ENC C§11.7: provisioning; soft: SSH C§12.5: who may log in; soft: HARN C§7.10: attaching to an enclave's Harness; soft: BAL C§9.6: enclave charges
- Provides: the enclaves' end-to-end scenarios; `TestComputeEnclaveLifecycle` (proposed)
- Files: server/sidecare2e/compute_world_enclaves_test.go, server/sidecare2e/compute_enclaves_test.go, server/sidecare2e/compute_enclaves_concurrency_test.go
- Build: §18's enclaves, setup-over-SSH and harness-management rows across the device, the broker's orchestrator and the guest, in the compute world with FakeEnclaveProvider: create (the provider's disclosure first, kind 19 on an approving device, the broker's create under its Idempotency-Key), attest, provision, enroll as the sponsor's device, SSH, attach and manage, stop, start and remove; a retry only by the device, as a new incarnation, at most 3; each state before `running` failing at its timeout and destroying its VM; steps 2-9 resumed by another device of the sponsor; a suspension stopping every enclave but the indexer and a top-up restarting those it stopped; an enclave interval delivered again after the cache is lost charged once; concurrency: several sponsors creating and stopping at once under one orchestrator lease an enclave, a lease moved mid-interval written once. Traps: the reference provider's hardware runs (Google's TDX, the self-hosted SEV-SNP host) are External; this is the stack on fakes.
- Tests: TestComputeEnclaveLifecycle; TestComputeEnclaveRetriesAsNewIncarnations; TestComputeEnclaveStateTimeouts; TestComputeEnclaveResumedByAnotherDevice; TestComputeEnclaveSuspensionAndTopUp; TestComputeEnclaveIntervalChargedOnce; TestComputeEnclaveConcurrency.

### CTEST-M15-01: The TEE path's fakes and end to end
- Milestone: M15
- Repos: sidecar, server
- Size: L
- Spec: C§18
- Needs: CTEST-M12-05; CTEST-M12-06; CTEST-M14-01; soft: INFER C§6.6: the TEE path and its E2E client; soft: ATTEST C§5.3: GPU evidence through NRAS; question compute-plan-adapters-before-commitment
- Provides: `computetest.FakeInferenceProvider.ServeTee` (proposed); `computetest.FakeTeeEvidence.GpuEvidence` (proposed); the TEE path's end-to-end scenarios
- Files: sidecar/sidecartest/computetest/provider_tee.go, sidecar/sidecartest/computetest/provider_tee_test.go, sidecar/sidecartest/computetest/tee_gpu.go, sidecar/sidecartest/computetest/tee_gpu_test.go, server/sidecare2e/compute_tee_test.go
- Build: §18's attestation, E2E-client and cache-salt rows on the TEE path (M15, at G-PROV-chutes). FakeInferenceProvider's TEE half (`ServeTee`): evidence for a chute by nonce over the device's own TLS through the broker's tunnel (FakeTeeEvidence with SPDM GPU evidence), `/e2e/instances/{chute_id}` answering instance keys and one-use nonces under a test API key, `/e2e/invoke` opening the envelope by Chutes' documented construction (ML-KEM-768, HKDF-SHA256, ChaCha20-Poly1305, a fresh ephemeral key per request), written apart from INFER's client so a mistake shared by both cannot pass, streaming sealed chunks and `ur_usage`, a 429 at capacity, a prepare whose keys cover fewer than half the listed instances. FakeTeeEvidence's `GpuEvidence`: NRAS-style tokens signed by a test key chaining to a test root, DevTools mode, missing evidence, OCSP revoked. End to end in the compute world: a TEE model answering through the Harness and Codex with a verified AttestationResult in the record; a failed attestation refusing with nothing sent elsewhere; two devices of one member and their enclave sending one cache salt, a tagged device its own. Traps: the Chutes path waits for SN64's gamma and Chutes' agreement (question compute-plan-adapters-before-commitment); the live E2E path per release is External.
- Tests: TestFakeChutesEnvelopeRoundTrip (sealed by INFER's client, opened here, and the reverse); TestFakeNrasTokenVerifiesUnderTheTestRoot; TestComputeTeeCallEndToEnd; TestComputeTeeAttestationFailureRefuses; TestComputeCacheSaltPerMember.

## Appendix B: tip-check's findings on 2026-11-27

Each red is the build's evidence for today. Several are worth an e2e look under load.

| Test | What failed | Cause | Fix | State |
|---|---|---|---|---|
| sdk `TestForwardClientLapsesUnrefreshed` | A forward client's lapse decision raced | A real race in sdk's forwarding | `forward-lapse-decision-race` | Landed |
| sdk `TestDeviceLocalSyntheticDeviceRemoteMemorySoak` | One unexplained compact-route rejection | A completed TCP flow's late packet; connect now counts the refused generation (`FlowGenerationDropCount`) | `sdk-soak-unexplained-rejection` | Landed; the counter is not yet carried across a replaced multi client, nor exposed in `PacketStats` |
| sidecartest enginenet | A scope-before-gate failure | A race in the test, not in the token exchange | `enginenet-scope-gate-race` | Landed |
| cli `TestDarwinDiscoveryProxyLeavesATakenNameOut` | "no apply within 10 s" | A real-time bound against this Mac's mDNSResponder under load | `darwin-discovery-test-bound` | Landed |
| sidecartest/fault `TestFs56` | FS-56's twin, seed 8: "the first echo was never answered" | By design under load: the host NAT drops a new window's first reply, and darwin drops replies at its datagram ICMP socket | `fs56-twin-first-echo`, which resends each echo every second while a wait needs it; server's T3 copy is `server-bridge-echo-resend` | Landed |
| cli `TestDaemonClockCapChecksTheCoreEachInterval` | "the cap checked no core clock", 1 run in 6 | The clock sweep (QD-1425) moved the shared-block judgment onto the daemon's clock, so the test's `AwaitTimers(1)` could count the wrong timer | `sweep-later-followups` | Landed |
| check `TestComputeStaysOffTheSidecarHttpLeg`, `TestLegs` | The js/wasm page leg compiled compute custody files | Two tracks, each green alone: one landed the files, the other the rule | Inside `secret-matcher-reader-keys` (sidecar `648ccf71`) | Landed; three tracks landed past it meanwhile (QD-1446 to QD-1448, QD-1450) |
| sdk `TestSidecarLocalKeepsTheAppsSupportLog` | 0 app.started and 0 app.stopped | The app's support log is deferred until the instance opens, and the test closed first | `sdk-support-log-test-wait`; QD-1451's refusal in `SupportLog.Start` is `support-log-start-after-close` | The test landed; the refusal is running |
| sidecartest/fault `TestFwdAppWithinTargets` | FS-38, seed 0: the host never adopted config version 8 (state 7, a compile wanted, no waiter, no alarm) | Possibly a lost wake after the clock sweeps | `fwd-compile-wanted-stall` | Running; passed 340 runs alone, failed 1 of 112 rounds |
| sdk `TestLicenseYmlUpToDate` | license.yml lacked `ebitengine/purego` | The safety classifier's ONNX Runtime binding (SAFE-M13-03) | `sdk-license-purego`; QD-1455's check of replaced siblings' license texts is `sdk-license-check-replaced-texts` | Landed; the check is queued |

Two more things from today:

- **An image dependency bump.** `x-image-vuln-bump` raises `golang.org/x/image` past GO-2026-6222 in every module
  (QD-1454). Until it lands, the gateway refuses an oversized WebP with 400.
- **The secret matcher's keys.** It now holds the device's ReaderKey seeds and the fixed-count keychain keys (QD-1444,
  QD-1449). Per-repo RK_g waits for a bounded matcher, and until then one in a tool result passes unchecked.

## Appendix C: failures that come from the host, not the code

REVIEW-HANDOFF.md's section 6 lists them. In short:

- **Durable blob tests.** Twenty server tests need a Linux ext4 host. On a Mac's APFS they fail on the descriptor
  identity; on an external volume mounted noowners they fail earlier.
- **Private resources.** `TestIpInfo` and its neighbours need settings.yml's `ip_overrides` and a tls.yml that a
  portable root lacks.
- **`-trimpath`.** Three env tests fail under `-trimpath`, which the build's wrapper sets. So do server/api's
  `TestSpecConformance` family, which cannot then find connect's `bringyour.yml`.
- **oauth.** Its 12 DB tests need an `auth.yml` the private stack's vault lacks.
- **Gate matrices.** Every gate's §19 matrix fails rows R-OPS-7 and D-OPS-6 while `build/server` is a stale copy.
- **T3's purge.** T3's stack records no `settle_passed_build`, so the evs block's purge deletes nothing there. Its
  deletes are proven only on T2.
- **Python.** connect's and xops's Python tests need PyYAML and Jinja2.
- **warpctl.** 14 of its run-worker and retirement tests fail on macOS (no `/proc/self/fd`, no docker).
- **connect's performance matrix.** `TestWindowPathServicePerformanceMatrix` fails on connect's own `main` too, in a
  few rate, rtt and compression cells.
- **Load.** `TestPrivacySearchQueryCanaries` is load-sensitive. So are the real-time-bounded tests Appendix B names.
