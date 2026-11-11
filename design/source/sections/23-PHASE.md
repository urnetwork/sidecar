## 23. Phasing, milestones, and rollout

### 23.1 Purpose and scope

This section owns X15: milestones M0-M10 on two tracks, staffing, exit criteria, the gate map, freezes, lead times, publication and merges. What each milestone builds belongs to §4-§18 and §21; environments, hardware and releases to §19; tests and gates to §22.

### 23.2 Requirements

| id | requirement | source |
|---|---|---|
| R-PHASE-1 | Design peer review precedes implementation | CONVENTIONS.md preamble |
| R-PHASE-2 | Work stays on `sidecar` branches; `main` stays production-ready | owner rule 4; build/README.md:5 |
| R-PHASE-3 | Services land vertically, sidecar to server; sidecar imports only connect | PLAN.md:7, :36 |
| R-PHASE-4 | recURd's three stages ship whole, in order, at ur.io/recurd: record and reach; team layer and TLS edge; inbox and assurance | sidecar/design/pitch5.html:889-907; owner decision 15 |
| R-PHASE-5 | Design partners and trust documents come first; the documents, disclosing unaudited cryptography, gate the "end-to-end encrypted" claim | sidecar/design/pitch5.html:886-887, :909-934; owner decisions 99, 119 |
| R-PHASE-6 | No sidecar ships before the AUTHZ1 P0 and 7-day sidecar tokens | D-TRUST-3; owner decisions 45, 103, 131 |
| R-PHASE-7 | Burner email needs inbound mail, mailboxes and app seams; outbound mail waits for sound BDAT and DATA proofs | [R:product] §2.3; owner decisions 35, 99, 125 |
| R-PHASE-8 | Migrations deploy before code and stay compatible with the running release | connect/CODESTYLE.md:87-89 |
| R-PHASE-9 | sidecar goes public now, as it is; every touched repo merges at each exit review | owner decisions 117, 118 |
| R-PHASE-10 | Two tracks after the shared M0-M2, the second with its own team; mail's lead times start in M0 | owner decision 9 |
| R-PHASE-11 | Format 1 freezes only on §22.8's measured fit of the 8 × PM9A3 metadata set (≤ 0.8 DWPD, ≤ 50% of rated IOPS, at 2× year one's mix, which P0 work past the refill can pass), and format 2, with the index on by default, on the same fit projected from that measurement, then confirmed on production after its freeze; the tier grows by whole clusters | owner decisions 136-140, 145, 156, 174, 186 |
| R-PHASE-12 | Page-class infrastructure alerts reach an out-of-hours rota from M3 | owner decision 143 |
| R-PHASE-13 | Versionless objects, the search index and search in `ur` and MCP ship in v1 as storage format 2; format 1 reserves their numbers at M2 and refuses them cleanly; repos created before format 2 migrate | owner decision 163 |

### 23.3 What exists today

- No repo has a `sidecar` branch; sidecar is PUBLIC since owner decision 118's flip, its two `main` commits holding only documents (§4.3).
- Releases check out `main` in every repo (build/all/run.sh:666-671, :825-876). server's lock pins each sibling's commit (server/local/source-graph/lock.yml:7-39), checked against each HEAD (server/local/source-graph/source_graph_test.go:135-141); sn builds server's packages and repeats its replaces, which Go does not inherit (sn/go.mod:212-215).
- A migration's version is its slice index plus one (server/db_migrations.go:163-165), so an applied migration cannot move.

### 23.4 Milestones

Each milestone is a vertical slice (PLAN.md:36) with entry and exit reviews and a dark deploy. RS1-RS3 are recURd's stages (sidecar/design/pitch5.html:892-904; RECORD.md, §16.8), each released once its last item lands; BS1 is the burner launch. **v0** is what personal networks get, M0-M5 and M7-M9, with app hosts at M8; **v1** is M6, M10 and M7-M9's Team items, M10 bringing versionless objects and search to every network (owner decision 163); **Later** follows M9 and M10. `sidecar` branches start at M0 in every touched repo (owner decision 196): sidecar, connect, server, sdk, build and sn, which must repeat server's sidecar replace (23.3); xops for D-OPS-18's dumps; warp for §19.11's W5, W2 and W8; mmm; config (pro.yml's `sidecar:` blocks, `preview_networks`); vault; and the minio fork for D-OPS-20's build (owner decision 195). M0-M10 build straight through on those branches, in dependency order; 23.8 says what happens at a gate the build cannot meet (owner decision 194).

| M | Scope (owning §) | Exit criteria (§22) |
|---|---|---|
| M0 Foundations | G0, signed by the owner (owner decision 193); RECORD.md drafted; §4's pre-code v0; §7.4's stage 1 and D-TEAM-14, log-only; §10.4's subset begins, with its X-Wing KAT; §12's census and renewal; `smtpproof` begins | G0 passed; `make check` green; lock entry on server@sidecar; P0 log-only in production; the sidecar dump daily from MG0's Gn-out, its tables excluded from the main dump (D-OPS-18) |
| M1 Core, subprotocol | §5, §6 and §7 v0 up to the config repo, with the narrow `ur-cli`; §20's `sidecar:` blocks, counters and 20.8; C3, C11, C12, C15 | stage 1 and D-TEAM-14 enforced; Required RPC after §6.4's M1 identity check; push resyncs after a resident restart; envelope fuzzed; daemon on darwin, linux and windows, in `preview_networks` only (D-TRUST-3) |
| M2 Storage | §7.9's config repo, key authority with its presence countersignature (owner decisions 185, 187, 189, 192), leaf rule and `IndexerSet`, §8's projection, gates and owner consent, §6's HeadCheck and witness bound, and §10 v0 with agents on wraps (owner decisions 3, 5, 110, 112-114, 126-129, 144, 150); §11 v0a and v0b, with git-mode tip CAS, creation-time placement and the write budget with its accounts, wallet and P0 reports (owner decisions 140, 141, 145, 186, 190); format 1's reservations (owner decision 163; D-PHASE-9): format 2's numbers, the drop's EvsPush flag 256 and field 33, the erasure cut's flag 512 and field 34 with EvsHead's index_epoch, window bit 5 and read states `drop_pending` and `dropped` among them, and the directory's (repo/'s `directory` kind with §8.5's kind default, acl.proto's `autogroup:dst-owner` atom, which the implicit document's directory rule names, and `EvsShare.expires`, both honored from M2, and config.proto's `ServiceSettings.directory`); the slot rule as a format-1 check (§11.8's 5h and step 6; §11.22); specifications frozen at Gn-in and formats at Gn-out (23.8); §20's debit path, relayed bytes included; a staging file cluster on the production hosts and their PM9A3 set (§19.11) | D-KEYS-10's plan, fuzz targets and sizes, and §22.10's 0x0010 interop artifact (§10.4); 23.6's M2 schedules, FS-57 to FS-63, FS-113, FS-114's head and marker cases, FS-116 to FS-118 and FS-72's and FS-95's format-1 cases included; twenty agents, §11.15's targets and §22.8's storage benchmark, whose nvme run's gate is at most 43 KiB written per push per drive at 2× year one and 50% of rated IOPS on the PM9A3 set (D-TEST-11); servers get only §2.8's evs and gkm fields; §22.7's admission suite, consent and recovery veto included |
| M3 Capture pilot | §16 v0 with `run_restore`, owner decision 142's tainted-run evidence and `EvsShare` readers' receipts (D-MCP-18), before which owner-bound shares stay closed (§8.19); `record.proto` frozen (23.8), CanonicalAction's field 37 reserved for format 2 and approvers refusing an action version they do not know; the production file cluster on M2's hosts, rebuilt empty and SMART-rechecked (D-PHASE-7); the out-of-hours rota (owner decision 143); §5's device revocation with its presence check and `ur devices` (D-CORE-20) | hook conformance for Claude Code, Codex and Cursor; approval crash and replay effect counts (§22.7); restore writes only attributed paths and loses no concurrent write (§22.7's restore suite, FS-115); coverage names every gap; production file cluster, re-seed drilled (§19.10); the write budget live on the production metadata set, its drive counters, SMART wear, class liabilities and each cluster's exhaustion projection in monitor (§19.6, §19.8); the hdd run's admitted mix under the 50% policy (§22.8); FS-119's cohort drill; the main dump on schedule, the sidecar dump daily, one restore drilled (19.10); §7.4's stage 2 live; pilot on personal networks (owner decision 102) |
| M4 Reach; RS1 | §8's requested grants, suspension and contract gate, with witnesses' `control` contracts (D-PROTO-18); §17 v0 with `ur tun`'s private names (owner decision 85); C5, C6a, C8, C13, C14, C16; §18's dark seam; the minimal ur.io/recurd page (owner decision 223), its sign-in by hand-off from the ur.io session (owner decision 219), downloads and page Worker (§18.8; owner decisions 15, 26, 76); recurd.dev's redirect (§19.5); §20.9's escrow comparator (D-QUOTA-9) and §22.8's escrow benchmark harness, dark, with the comparator's index pending in MG6 (§19.7) | forwards, private IPs (Linux, WSL2) and model servers behind approved, expiring grants; suspension within one epoch; a Claude Code cloud agent reaches a granted port; ur.io/recurd opens a vault record; trust documents drafted |
| M5 Names, edge | §6 streams and Service edges (C9); §9, §12, §13 and §21 v0, with `tls/`, the dns edge, §7's edge login and §19.8's M5 pages (owner decisions 134, 143); §14's report host | the dns edge serves the user root, signed without a DS (owner decision 109); platform names and company MX off ur.network; passthrough publish; CT and zone watches alarm on a test certificate and record (owner decision 98); kill switch ≤5 s; FS-66's, FS-69's, FS-76's, FS-78's and FS-92's hold cases once M10's Gn-out has passed |
| M6 Team; RS2 with M5 | v1 of §4-§13 and §16-§21, less M10's format 2, with SCIM, custom domains, cross-network shares (C18, owner decision 86), config wraps for member devices past a network's first 1,000 (owner decision 144), the team directory on format 1's record streams (§16.11; owner decisions 170, 171, 179-182: its repo, group, `announce` entries, requests and decisions, `claims` and the instructions, `directory_list` and the request tools), `ur tun` on macOS and Windows and 24/7 on-call; the team console on the page Worker | all 133 `admin_user_id` reads classified; OIDC SSO; removal blocks writes until its Remove commits; the team record, reach receipts, verifiable log and client packets (§16.18); S13 with FS-84, FS-85, FS-86, FS-87, FS-88, FS-99, FS-100 and FS-101's M6 cases, and evs-27 in §2.8; the console shows members and policy; a custom host turns ready, and its TLS-ALPN-01 order starts, only once every lb interface is current for its map version (FS-122); Team billed; FS-76's and FS-80's team-record cases, FS-83's team cases and the directory's format-2 cases once M10's Gn-out has passed |
| M7 Inbound mail | §9's `smtp/`; §12's mail records, TLSA and the DS; §15's receive path; mxedge on TCP 25 | SNI inbound reaches desktop, NAS and VPS mail indexers (owner decision 150); DANE TLSA live; plaintext senders refused; validated labels (owner decision 135), from reception-time authentication inside §15.5's bounds (FS-121); D-MAIL-9's census run, with §14's outbound probe; FS-76's and FS-78's mailbox cases once M10's Gn-out has passed |
| M8 Burner; BS1, receive-only | §15's burners and app seams; §18's app hosts with §5's sdk hosts and wake pushes (owner decision 88); §13's app listeners; §17's forwarding in every app's VPN component, with its own key and compile (owner decision 197), app-device hosts after C16 and private names on app paths; §21's trusted flaggers; the directory's notice wakes on phones (§16.11) | burner create and burn, vault entries and one-time codes through the bound API; the DeviceRemote mirror and receiver hosting API pass §22's T4; wake tokens projected in revision order (FS-120); release readiness, never a per-user gate (owner decision 12): the mail indexer paths (desktop daemon, NAS or VPS; no app, owner decision 197) and the apps' indexer prompt pass §22, and `CreateBurner` shows the `foreground-only` copy before a first burner when coverage is `foreground-only` or `none` (§15.9); FS-77's, FS-83's and FS-125's app-host cases once M10's Gn-out has passed |
| M9 Outbound mail | §14 v0 on the shared lb addresses (owner decisions 35, 99, 124, 125), with §9's `ur/`, §12's reverse zones and burner records, §15's sending, replies and forwarding (owner decisions 53, 79) and §21's mail ladder and breakers | D-SMTP-16's tests (14.5), DATA mode included, with per-recipient send checks and outcomes (FS-123); DANE-only MXs reached and unauthenticated ones refused (TL1; owner decision 38); halt, ARF and RUA joins |
| M10 Format 2, beside M6 (owner decision 169) | §11's format 2: versioning per version, kind-5 and staged content, the purge, the network's default rule (§7.9) and the repo lock (§8.8), git-lfs's versionless store and the migration of format-1 repos (owner decisions 158, 160-165), and the drop-history action behind §19.11's `format2.drop` gate, observe first (owner decisions 173, 183, 184); the search index in every eligible repo, with indexers' `search` service (owner decisions 150-157, 159); §11.14's remote search, with indexers' serving side, app hosts' requester side and its keepalive, and C19's window accounting (owner decisions 175-178, 188, 191); §16.10's `ur search`, `ur agents` and MCP search tools, with §5.9's index cache (owner decision 166); the directory's cards, repo files and index (§16.11); §18.4's phone and page fetch rules; specifications frozen at Gn-in and format 2's bytes at Gn-out (23.8) | 23.6's M10 schedules on their tiers, FS-73's stock-client tip check, FS-83 with FI-24, FS-125, FS-86's card case, FS-89 to FS-96, FS-111, FS-112 and FS-114's purge and drop cases among them; D-TEST-13's drive-write gate, computed from M2's price table and T3's counts (owner decision 174); the remote, directory and drop benchmark rows; connect-5, evs-27's cards and evs-28 in §2.8; the index vectors byte-equal on every leg; a format-1 repo migrated with its first index build, its search equal to D-TEST-14's oracle; the purge and drops in observe mode, deletes waiting for D-TEST-12's and D-TEST-18's production soaks (23.9) |

**Later:** RS3, whole once its assurance items land: team legal holds (§16), compliance mappings, and self-hosted and air-gapped installs (owner decision 48); the extension's Worker and streams (C4); a designated-verifier prover (§14); §17's IPv6 subnet routes; the PSL listing; a move tool for placed repos (owner decision 145); evs compaction and the reclaim of expired ciphertext (owner decisions 246, 247); working-tree sync and derived shares (owner decision 250); embedding search on indexers (owner decision 150); delegating tasks to a worker's agent and sharing its run sessions (owner decision 179). §7.4's stage 3 follows app adoption.

### 23.5 X15: two tracks and staffing

Team A (recURd) builds M0-M4 and M6; team B (mail and burner, owner decision 9) builds M5 and M7-M9, with four engineers by M2's exit: one from M0 on `smtpproof`'s BDAT and DATA proofs (owner decision 125) and mail's lead times, then one each for edges and DNS, mail ingress and receivers, and app seams. M5 is on track B because M7 needs its dns edge, DNSSEC soak, C9 and abuse intake, and RS2 its TLS edge. If team B is not staffed by M2's exit, team A builds M5 before M6, M7-M9 follow M6, and the owner hears then.

M10 is track A's (owner decision 169): about three more engineers, hired from M3's entry, build §11's format 2, the index and the search tools from M4's exit beside M6, about 9-12 engineer-months by inference; its hold, team, mail and phone cases wait for M5, M6, M7 and M8 (D-PHASE-8). If the engineers are not there by M4's exit, M10 follows M6, and the owner hears then.

M2's critical path is §10.4's subset (owner decision 43's 2-4 engineer-months) and §22.10's 0x0010 interop; §7.9, §11 and gkm build in parallel against a fake of the subset, and D-TEST-11's run needs the production hosts and their PM9A3 set before M2's exit (23.7). If either slips, M2's exit and every later milestone's exit slip with it, since both tracks share M0-M2; the build goes on, with formats unfrozen (owner decision 194; 23.8).

### 23.6 Decisions that block each milestone

Peer review closed every question owner decisions 1-135 left to it on 2026-11-04; owner decisions 141-145 decided the five it raised (Q-EVS-8, Q-MCP-6, Q-OPS-9, Q-KEYS-15, Q-OPS-10), owner decision 140's corrected record closed Q-EVS-9, owner decisions 146-166 settled the second round and the 2026-11-05 additions, and owner decisions 167-184 answered every v1 question (Q-EVS-19 to Q-EVS-23, Q-MCP-7 to Q-MCP-9, Q-SDK-6, Q-PROTO-4, Q-ACL-11, Q-KEYS-16, Q-ABUSE-7, Q-PHASE-9 and Q-PHASE-10; 23.12, Appendix B), owner decision 185 the SDK fixes' question, owner decisions 186-191 the final meta review's (Q-EVS-24, which owner decision 190 refines, Q-PROTO-4's answer, which owner decisions 188 and 191 amend, and the presence countersignature's reach), owner decisions 192-196 those of the implementation handoff, and owner decision 197 the apps' network extensions, whose design raised two owner questions: Q-SDK-7, which owner decisions 215 and 216 decide for M4's entry, and Q-BRIDGE-8, open now, at M8's (18.13, 17.14). The map puts each item at the review that needs it: a Gn-in needs its design closure, a Gn-out its schedules passing on their rows' tiers, each step at the Gn-out of the milestone that ships its mechanism. The owner keeps one launch call on measured data: accepting the SNI loss M7's census finds, before BS1 (D-MAIL-9; owner decision 34).

```text
gate     design closure at Gn-in (owning sections)                            schedules passing at Gn-out (§22)
G0       the module path (§4); the density rule (23.8), its review running    -
         beside M0's bootstrap (owner decision 193); every question in the
         M0-M2 rows
M0       the sidecar dump and the main dump's exclude list (§19); Q-TEST-1,   -
         Q-TEST-2 (§22)
M1       typed signing; transport-token states; the keystore result; HTTP     FS-54
         liveness; persistent taint and bridge anchor (§5, §6, §7, §18);
         Q-CORE-4, Q-TEST-6
M2       the head object and its pins; generation serialization; the          FS-1 to FS-12, FS-14 to FS-18,
         delta-prefix commitment; the recovery veto; ref witnesses; path      FS-19's config read, FS-20, FS-22 to
         epochs; the git model with git-mode tip CAS (owner decision 141);    FS-24, FS-40, FS-44, FS-45, FS-47,
         placement (owner decision 145); the config leaf rule (owner          FS-53, FS-57 to FS-63, FS-72's and
         decision 144); IndexerSet (owner decision 150); the ephemeral        FS-95's format-1 cases, FS-82's
         ceiling; deposit-only principals and the depositor rule; shred and   statement cases, FS-102 to FS-106,
         restore; staged versions; orphans; the path-directory bound; format  FS-113, FS-114's head and marker
         2's reserved numbers, the drop's and the erasure cut's included,     cases, FS-116 to FS-118, FS-124's M2
         and format 1's refusal of them (owner decision 163); the directory   cases; the nvme run (D-TEST-11);
         kind, its default and its admin-only erasure, autogroup:dst-owner's  §22.10's 0x0010 interop
         atom and the implicit document's directory rule, EvsShare.expires
         and ServiceSettings.directory; refusal records; the write budget's
         accounts, wallet and P0 reports (§6, §7, §8, §10, §11; owner
         decisions 186, 190); the store's deadline and settle rules (§19);
         Delegation key drops and ends (§7, §10); key deliveries' identity
         and authority, ReaderKey validity and gkm's route scopes (§10.5,
         §10.6, §10.9); the presence countersignature (owner decisions 185,
         187, 189, 192; §6, §7, §16); usage batches, relayed reservations,
         quota maintenance (§20); Q-CTX-4, Q-KEYS-11, Q-EVS-6, Q-OPS-2,
         Q-EVS-24
M3       approvals and effects; run attribution and restore's apply; harness  FS-25 to FS-30, FS-50, FS-115; FS-41
         evidence, tainted runs by owner decision 142; EvsShare readers'      and FS-42 on M3's mechanisms; FS-40
         receipts; CanonicalAction's reserved field 37 and approvers'         on production; the nvme and hdd runs
         refusal of an unknown version (§16); the recovery runbook,           on production before it holds data,
         protection state, the out-of-hours rota by owner decision 143        the hdd run's admitted mix included;
         (§19); a member's device revocation with its presence check (§5)     FS-119; FS-98's and FS-124's CLI
                                                                              cases
M4       witnesses' control contracts (§6, §8); C13's sealed source and the   FS-19's grant and share runs, FS-21,
         dial fence (§17); HTTP liveness (§18); the page Worker; the escrow   FS-37, FS-38, FS-56, FS-97 and
         comparator and index (D-QUOTA-9; §20); Q-BRIDGE-2, Q-SDK-5; the      FS-106's page Worker case
         forwarding leg's file list and budget, Q-SDK-7's (§4.7, §18.10;
         owner decisions 197, 215, 216)
M5       ALPN audience; the custom-SNI map (§13); report parsing (§14);       FS-34, FS-39's report-intake cases,
         hold kinds and abuse clocks (§21); Q-OPS-5                           FS-47's §21 case, FS-48, FS-49,
                                                                              FS-52; S7's SNI-less abuse@<root>
                                                                              case; FS-41 and FS-42's M5 steps
                                                                              (labels, TLS endpoints, the dns
                                                                              restore step); FS-66's, FS-69's,
                                                                              FS-76's, FS-78's and FS-92's hold
                                                                              cases once M10's Gn-out has passed
M6       the CAA chain (§12, §13); the audit reader's receipts and the team   FS-19's Team and invite runs; FS-21
         directory's specification: directory.proto's announcement, request,  on a Team default document; FS-30's
         decision, notice and erasure request messages, the kind and its      audit reader; FS-32, FS-35, FS-38's
         path rules, its admin-only erasure with the erasure runner, the      shares, FS-43, FS-51; FS-84, FS-85,
         decision protocol, its group under the leaves rule, its default      FS-87 and FS-88's M6 cases, FS-86's
         requests rule and autogroup:dst-owner, and §16.11's cost table with  M6 case on announce entries, and
         FS-86's ceilings (§7, §8, §10, §11, §16); config wraps for member    FS-99's, FS-100's and FS-101's M6
         devices past the first 1,000 (owner decision 144); C18's share       cases; 20.9's benchmark rerun; FS-41
         signers (§17); Stripe meters, downgrade (§20); the escrow order,     and FS-42's M6 steps (meters, custom
         frozen once FS-46 and 20.9's benchmark pass on M4's build            hosts); FS-122; FS-97's, FS-98's and
         (Q-QUOTA-3's residual); the custom-host map's versions, interface    FS-124's Team cases; FS-76's and
         reports and readiness (§12, §13, §19)                                FS-80's team-record cases, FS-83's
                                                                              team cases, the directory's format-2
                                                                              cases and FS-111's team-record case
                                                                              once M10's Gn-out has passed
M7       strict MX; receivers' deposits and their authentication bounds;      FS-13, FS-23's mailbox case, FS-33,
         mail labels; the census (§15)                                        FS-39, FS-121, FS-47's and FS-82's
                                                                              mail cases; FS-41 and FS-42's M7
                                                                              steps (mailboxes, mail host keys, a
                                                                              revoked receiver's TLSA); FS-76's,
                                                                              FS-78's, FS-111's and FS-112's
                                                                              mailbox cases once M10's Gn-out has
                                                                              passed
M8       wake dispatch and token revisions (§18); receiver coverage and its   FS-19's quick-burner run; FS-36;
         copy (§15.6, §15.9); the bound device revocation and its copy (§18); FS-120; FS-85's and FS-100's wakes;
         forwarding in every app's VPN component: the forwarding Delegation,  §22.5's forwarding cases; the mail
         the forward_only mark and its exchange rule, setup, following and    indexer paths and prompt;
         signing (§7, §10, §17, §18; owner decision 197); Q-BRIDGE-8          FS-82's coverage cases; FS-98's and
                                                                              FS-124's app-host cases; FS-41 and
                                                                              FS-42's M8 steps (push tokens);
                                                                              FS-77's, FS-83's, FS-109's, FS-110's
                                                                              and FS-125's app-host cases once
                                                                              M10's Gn-out has passed
M9       the SMTP server-state relation (§14); 22.10's M9 evidence; the       FS-31; FS-123; FS-42's M9 step (a
         send-capability and result model (§14, §15, §18)                     revoked sender's DKIM selectors)
M10      format 2: versioning per version, kind-5 and staged content, the     FS-64 to FS-81 and FS-89 to FS-96 on
         purge with its allowance and sweep, the migration and git-lfs's      M10's mechanisms, FS-72's migration
         store (§11), the network's rule (§7) and the repo lock (§8); the     and rollback cases; FS-83 with FI-24;
         drop-history action: the DROP push, fence, job and states (§11);     FS-125; D-TEST-13's projection; the
         the index's objects, encodings, field registry, partitions,          index vectors on every leg;
         coverage, exclusions, roll-up and lock, erasure cuts and rewrites;   EvsCommit.tla's purger and drop
         search.proto and the remote rules (§11); directory.proto's cards     extension, IndexRollup.tla; FS-66's,
         (§16); the search tools, scopes, caches and taint (§5, §16); the     FS-69's, FS-76's, FS-78's and FS-92's
         phone and page fetch rules (§18); §2.8's v7 rows as v8 amends them;  hold, FS-76's and FS-80's
         RECORD.md's search fields; §6.10's remote-search windows and         team-record, FS-83's team, the
         C19's window accounting (§4, §6)                                     directory's format-2 (FS-84's,
                                                                              FS-87's, FS-99's, FS-100's and
                                                                              FS-101's card and index cases,
                                                                              FS-86's card case, FS-88's search
                                                                              cases), FS-76's and FS-78's mailbox
                                                                              and FS-77's, FS-83's and FS-125's
                                                                              app-host cases, unless M5's, M6's,
                                                                              M7's or M8's exit follows (those
                                                                              rows); FS-111 and FS-112, their
                                                                              mailbox cases at M7's exit and team
                                                                              cases at M6's, if later; FS-107 to
                                                                              FS-110, their app-host cases at M8's
                                                                              exit, if later; FS-114's purge and
                                                                              drop cases
every    -                                                                    FS-55
Gn-out
next     §19.9's triggers, or their projection over its lead time, hosts      22.9's file-cluster suite and FS-63
metadata included; new repos placed on it, none moved (owner decision 145)    again, on the new cluster, and
cluster                                                                       FS-119 on T3, before place_new
                                                                              names it
```

### 23.7 External lead times

Each item gives (due; start).

- **Domains** (their dates; M0): ur.network expires 2027-07-02, renewed to 2036 (§12.4); bringyour.com 2027-11-15 (RDAP, 2026-11-03).
- **File cluster** (the hosts with their PM9A3 set before M2's exit, staging M2 for D-TEST-11 until M3 rebuilds them empty (23.4); the rest by M3; M0): §19.6's 4 hosts at one site, each with 2 × Samsung PM9A3 1.92 TB M.2 22110 (the 8-drive metadata set), 16 × 16 TB HDDs, 2 × 25 GbE and free NVMe bays; 2-4 PM9A3 spares and the cold spare chassis with its drives (owner decisions 20, 21, 94, 116, 136-139). The next metadata cluster, a tracked year-one item, is ordered when §19.9's triggers fire or monitor's 30-day trend projects one within its lead time, at about 1.25× year one's load (about 1.2× with v1's index on 4 KiB blocks). The second takes the hosts' free bays and later ones new hosts at the site, whose lead time the projection includes. §19.9 sizes year two's count from §22.8's per-push, per-object and per-batch measurements (D-OPS-17). The segment placement and added HDD capacity are ordered by §19.9's hdd trigger, ahead of year two's HDD load, and the move tool by its cohorts row, before the earliest projected cohort exhaustion.
- **`urnetwork/minio`** (before any push; M0): the owner creates the GitHub repo of D-OPS-20's fork (owner decision 195).
- **LE domain override** (M5; M0): "a few weeks", untimed (mmm/lag.dev/ops/letsencrypt.md:291-294).
- **dns edge** (M5; M0): two new hosts at the site, with their own addresses (owner decisions 69, 71, 123).
- **Platform names, company MX** (M5; M2): off ur.network before the NS switch (§12.4).
- **On-call, abuse readiness** (M3, M5, then M6; M2): a two-person out-of-hours infrastructure rota on one pager service, 30 min to acknowledge before escalation (owner decision 143); DMCA agent, registrar and Search Console contacts, business-hours abuse review, and registrar, registry and law-enforcement notices on that pager from M5 (owner decisions 95, 134); 24/7 review from M6 (§19.8).
- **Counsel** (M5; M3): confirms owner decision 133's condition and each hold kind's applicability (`preserve_2703f`, `report_2258a`) before holds ship (§21.9).
- **DNSSEC** (M7; M5): 30 clean days before the DS (§12.6).
- **HE TCP 25 egress, reverse delegation, feedback loops** (M9's entry; M0): unknown, so ask first; PTRs name bringyour.com hosts (owner decision 124; §14.9).
- **App releases** (M3, then M8; M1): 18.7's credential rules, in the desktop app and extension releases that stop persisting `by_jwt` (the extension's in `chrome.storage.local`), before §7.4's stage 2 (owner decision 45; D-SDK-11, D-TRUST-3), then the burner and bridge seams (§18.15).

### 23.8 Review gates

- **G0.** Peer review of DESIGN.md; the density rule: no content duplicated across sections (each item in its owning section, cited elsewhere), normative formats and state machines in fenced blocks, prose dense; D-ARCH-4's assembly check passes; 23.6's M0-M2 items settled; RECORD.md reviewed here or by M2's entry. The density rule replaced the OUTLINE word ceilings (+10%) on 2026-11-04: the normative formats and state machines peer review required put every section over its ceiling (the assembly's word table), and a ceiling cuts normative content where this rule cuts repetition. The owner signed G0 on 2026-11-06 (owner decision 193). A reviewer's re-check of the 21 items DESIGN-REVIEW-RESPONSE.md places at G0, the density review and RECORD.md's draft run beside M0's bootstrap, and their findings return as Q- items (D-PHASE-2), so a finding can change something already built.
- **Freezes.** With no external review (owner decision 99), each format freezes twice: its specification at Gn-in, its bytes at Gn-out on 22.10's evidence, whose FS rows are 23.6's schedules for that gate (D-PHASE-7). At M2: §7.9's records, its presence row and §6.9's countersignature fields among them (owner decisions 185, 187, 189, 192); format 1, whose bytes, D-PHASE-9's reservations included, also wait for D-TEST-11's nvme gate, its erasure and deposit bytes freezing on §22.5's §11 tests, FS-23 and FS-47 while FS-13, FS-23's mailbox case and FS-47's mail case keep their M7 gates; credential 0xF552, suite 0x0010 and D-KEYS-10's delivery wire (ReaderKey, KeyDelivery and gkm's wrap and recovery paths), whose bytes freeze with §22.10's 0x0010 interop artifact, a gap in any step it requires holding the freeze unless a second peer covers that step. At M3: `record.proto`, owner decision 142's tainted-run rule and CanonicalAction's reserved field 37 included. At M6: the escrow order (D-QUOTA-9), frozen at M6's entry once FS-46 and 20.9's benchmark pass on M4's dark build, the benchmark rerunning at its exit; `directory.proto`'s announcement, request, decision and notice messages, specified at M6's Gn-in, bytes at its Gn-out. At M9: `smtpproof/SPEC.md`. At M10: format 2, with the DROP payload and `directory.proto`'s cards, its bytes also waiting for D-TEST-13's computed gate (owner decision 174), repos migrating only after it (23.9); `search.proto`'s messages, types 0x1404 and 0x1405 and Hello's feature bits 0 and 1, additive to M2's wire.
- **Gn-in.** 23.6's design closure for the gate; specifications freeze; changes since G0 and §22's exit-test plan reviewed.
- **Gn-out.** Exit criteria shown, with 23.6's schedules passing; formats freeze; §22's privacy assertions pass; §2.8's list updated (I-18); `commit-msg --scan main..sidecar` clean (connect/CODESTYLE.md:83); the owner approves the deploy and merges (23.9).
- **Gates the build cannot meet.** M0-M10 build straight through in dependency order on the `sidecar` branches, with no stop at a Gn-out (owner decision 194). Each gate's local checks run and are reported, and anything needing hardware, production or people stays listed open: M2's format-1 freeze on D-TEST-11's PM9A3 run, M0's and M1's stages in production, each Gn-out's approval to merge. This changes how the milestones are executed, not what freezes when: the Freezes order above still decides what may reach a production store (D-PHASE-7). Formats stay unfrozen meanwhile, so a later hardware miss can force rework in later milestones.
- **Releases.** D-TRUST-3 holds; RS1's copy discloses I-10's no-policy allow-all (owner decision 120); "end-to-end encrypted" waits only for D-TRUST-4's document, §21.11's canary and §2.18's unaudited-cryptography disclosure (sidecar/design/pitch5.html:932-934; owner decisions 77, 119); BS1 waits for 23.6's census call and M8's mail-indexer readiness, never for a user's indexer (owner decision 12).

### 23.9 Branches, merges, and the source-graph lock

1. **Publication.** sidecar is public from owner decision 118's flip (2026-11-04), as it is (owner decision 117); every `sidecar` branch uses its repo's normal remote (§4.8).
2. **Merges.** At each Gn-out, every touched repo merges `sidecar` into `main` in §4.8's order (D-REPO-5), re-pinning the lock (23.3); deploys, pilots and releases build from `main`, gated in `config/<env>/sidecar.yml` (D-OPS-10).
3. **Migrations.** §19.7's groups stay pending under `sidecar_pending` (D-OPS-6) until their own Gn-out registers them, and never change after (23.3), so one track's merge never applies the other's group (FS-54) and M3's pilot runs on production (owner decision 118).
4. **Format 2.** After M10's Gn-out, §19.11's `format2` gate opens to internal networks and design partners; admitted networks' repos migrate as §11.6 states; the purge runs in observe mode until D-TEST-12's production soak shows no candidate a retained version names, then deletes; drops run in observe mode until D-TEST-18's soak, then delete (D-PHASE-12); D-TEST-13's production confirmation runs while the gate admits only those networks, a miss holding it there (owner decision 174); and only then does the gate open by percent (D-PHASE-10).

### 23.10 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Merges held until RS1 on private mirrors (owner decision 107) | no unreleased server code public | pilot and edges wait or run on canary | rejected (owner decision 118) |
| One freeze per format | one review | at Gn-in, no implementation evidence; at Gn-out, no fixed specification for M2's parallel work | rejected (D-PHASE-7) |
| Format 2 inside M6 | v1 as defined today; one fewer milestone | RS2 waits for an unrelated feature; M6 grows by ~9-12 engineer-months | not taken (owner decision 169) |
| Versionless fields in format 1 at M2, their collection later with the index | the cheapest format change | the owner chose v1 with a new format (owner decision 163) | ruled out |
| D-TEST-13's gate computed from M2's price table and T3's counts, confirmed on production after the freeze | no hardware bought early | a miss found after the freeze costs clusters sooner or a format change | chosen (owner decision 174) |
| The next cluster's 8 × PM9A3 as M10's staging set | measured before the freeze | drives bought ahead of the trigger, its model fixed early | not taken (owner decision 174) |

### 23.11 Decisions proposed

**D-PHASE-1 (proposed).** Build 23.4's milestones in dependency order, straight through on the `sidecar` branches (owner decision 194; 23.8), staffed as 23.5 proposes, releasing each recURd stage once its last item lands. *Why:* R-PHASE-4, whose stages ship whole (sidecar/design/pitch5.html:907), and R-PHASE-10; the sections' Phasing share these dependencies; and several gates need hardware, production or people the build does not have, where stopping at each Gn-out and building M0-M2 then re-planning were not taken.

**D-PHASE-2 (proposed).** No code is written before G0, which the owner signed on 2026-11-06, its re-checks, density review and RECORD.md draft running beside M0's bootstrap (owner decision 193; 23.8); an unsettled blocker defers what it blocks; until the owner decides an open question, text written at its recommendation is marked "(proposed; Q-...)" (D-ARCH-4); and an implementation finding that changes a D- item returns to review as a Q- item, as do those re-checks' and that review's findings. *Why:* R-PHASE-1; owner rule 8.

**D-PHASE-3 (proposed).** §7.4's stage 1 and D-TEAM-14 reach production log-only at M0's Gn-out, so the 14 log-only days overlap M1; the desktop app and extension releases with §18.7's credential rules, then stage 2, reach production before M3's pilot; until stage 2 is live, sidecar enrollment is limited to `config/<env>/sidecar.yml`'s `preview_networks`. *Why:* D-TRUST-3, kept off the critical path.

**D-PHASE-4 (proposed).** 23.7's M0 items, and §10.4's MLS subset with its X-Wing KAT, start in M0. *Why:* each is slow or unpredictable to finish, and the subset is M2's critical path (23.5).

**D-PHASE-5 (withdrawn).** Superseded by owner decision 118: every touched repo merges `sidecar` into `main` at each Gn-out (23.9).

**D-PHASE-6 (proposed).** The design-partner pilot starts at M3's exit; its measures (sidecar/design/pitch5.html:913-920) feed M6's entry review, which may re-plan the recURd track. *Why:* "Rework the developer hook before building the team layer" (:915).

**D-PHASE-7 (proposed).** Each frozen format freezes twice: its specification at its milestone's Gn-in and its final bytes at its Gn-out, on 22.10's evidence (23.8); no production store holds a format before its final freeze. The escrow order (D-QUOTA-9) is the one Gn-in that needs implementation evidence: M4 builds it dark, and M6's Gn-in freezes it on that build (23.8). *Why:* an entry review cannot show implementation evidence unless an earlier milestone built the code, and owner decision 92's hot-path benchmark must pass before M6's billing builds on the order; data on local, T3, canary and the staging cluster is rebuilt, so a change between the two freezes costs no migration.

**D-PHASE-8 (proposed).** Format 2 is milestone M10 (23.4), built on track A from M4's exit beside M6 with its own entry and exit reviews; no recURd stage waits for it, and its hold, team, mail and phone cases run at the later of M10's exit and, respectively, M5's, M6's, M7's or M8's. *Why:* owner decision 169 places it, and owner decision 163 puts all of it in v1; RS2's items (sidecar/design/pitch5.html:897-899) do not include search, so holding RS2 for format 2's freeze would delay a release for another feature.

**D-PHASE-9 (proposed).** A format that freezes reserves the numbers a decided later format or milestone needs. Its code refuses data that uses a later format's numbers as needing that format, never as tampering; knows a reserved kind, applying its fixed kind default (the `directory` kind's readers and writers, §8.5, D-ACL-24); ignores a field that only guides writers; and from the freeze honors a reserved access limit and evaluates a reserved policy atom, as the implicit document's directory rule names `autogroup:dst-owner` from M2, Team documents from M6 (§8.4, §8.5). Format 1 reserves at M2 format 2's numbers, the drop's and the erasure cut's among them (EvsPush flags 256 and 512 and fields 33 and 34, EvsHead's index_epoch, window bit 5, the read states `drop_pending` and `dropped`), and M6's directory's: the `directory` kind, acl.proto's `autogroup:dst-owner` atom and `EvsShare.expires`, and config.proto's `ServiceSettings.directory` (§7.9, §8.4, §8.8, §10.5, §11); the search index's own encoding (`evsindex.proto`, sealed inside the versioning-2 files format 1 reserves), its tombstone tables and diff rules included, needs no number at M2 and freezes with format 2 at M10 (§11.14); `record.proto` reserves CanonicalAction's field 37 at M3 (§16.8); no number is reserved for keep-last-n (owner decision 165). *Why:* owner decision 163, and the directory (owner decisions 171, 180) writes into formats that freeze at M2; an upgrade must not raise fork or missing-segment alarms on older devices, a config field or atom that older devices refused would stop the network, and a reader that ignored a share's expiry would widen access.

**D-PHASE-10 (proposed).** Format 2 reaches production only after its final freeze, through §19.11's `format2` gate in 23.9's order, and deletes replaced versionless content only after D-TEST-12's soak and dropped history only after D-TEST-18's (D-PHASE-12). *Why:* D-PHASE-7's data rule; a purge or migration bug must surface on internal data first.

**D-PHASE-11 (proposed).** The directory ships at M6 on format 1: announce, request, decision, erasure request and coordination entries in its streams, read 64 to a request (§11.9), and versioned notices; its erasure takes `admin` in M2's code, as every repo's (§11.12). It moves to cards, repo files and its index with M10, its format-2 cases running at the later of M6's and M10's exits. M2 reserves its kind, atom and fields (D-PHASE-9). *Why:* owner decision 169 keeps RS2 off format 2, and owner decision 170's announcements need only streams.

**D-PHASE-12 (proposed).** Drop deletes reach production only after D-TEST-18's soak, through §19.11's `format2.drop` gate in 23.9's order. *Why:* as D-PHASE-10, for the costlier delete path (owner decision 173).

### 23.12 Open questions

**Q-PHASE-1.** [X15] In what order are the products built after M2? **Decided by owner 2026-11-03 (owner decision 9):** (c), two tracks, a second team on mail and burner (23.5). *Residual:* none.

**Q-PHASE-2.** Does RS2 wait for email approvals? **Decided by owner 2026-11-03 (implied by owner decision 80):** moot. *Residual:* none.

**Q-PHASE-3.** When does cloud-agent reach ship? **Decided by owner 2026-11-03 (owner decisions 22, 49):** M4, through C8 and §18.9's rung 2. *Residual:* none.

**Q-PHASE-4.** How do pilot teams enroll before M6? **Decided by owner 2026-11-03 (owner decision 102):** (a), one personal network per developer; team measures wait for M6. *Residual:* none.

**Q-PHASE-5.** When do external reviews run? **Decided by owner 2026-11-03 (implied by owner decisions 99, 102):** moot; 22.10's gates stand in. *Residual:* none.

**Q-PHASE-6.** Which burner root and label size does M8 use? **Decided by owner 2026-11-03 (implied by owner decision 32):** moot. *Residual:* none.

**Q-PHASE-7.** How is token expiry enforced before the first sidecar? **Decided by owner 2026-11-03 (owner decision 103):** (b), D-TEAM-14's hard 7-day `exp`, shipped with the P0. **Decided by owner 2026-11-04 (owner decision 131):** only sidecar-held child and admin-refused tokens get it, and the sdk's window clients keep today's lifetime until app adoption (§7.4). *Residual:* none.

**Q-PHASE-8.** When does sidecar go public (Q-REPO-4)? **Decided by owner 2026-11-04 (owner decision 118):** now, as it is (owner decision 117), superseding owner decision 107; every touched repo merges at each Gn-out (23.9). *Residual:* none.

**Q-PHASE-9.** Where in v1 does format 2 go, and who builds it? **Decided by owner 2026-11-05 (owner decision 169):** (b), its own milestone M10, on track A from M4's exit beside M6, with about three more engineers hired from M3's entry; RS2 does not wait, and M10's team-record, mail and phone cases run at the later of M10's exit and M6's, M7's or M8's (D-PHASE-8). Options (a), inside M6, and (c), after M6, were not taken; (c) stays 23.5's contingency if the hires slip, and then returns to the owner. *Residual:* none.

**Q-PHASE-10.** Cross-cutting (§19.6, §22.8). Which drives run D-TEST-13's drive-write gate before format 2's bytes freeze? **Decided by owner 2026-11-05 (owner decision 174):** (b), none: the gate is projected from M2's measured price table (§22.8) and T3's operation counts with the index on in every eligible repo, then confirmed on production after format 2's freeze, while §19.11's `format2` gate admits only internal networks and design partners (23.9), by the write budget's measured-over-priced ratio staying within 10% (D-TEST-13); no staging drives are bought early, and a miss found after the freeze costs more metadata clusters sooner (owner decision 145) or a later format change. Options (a), early staging drives, and (c), synthetic repos on production, were not taken. *Residual:* none.

### 23.13 Departures from PLAN.md

- **PLAN.md:31** ("The initial goal for the sdk is to expose the features of the new services"). sdk exposure arrives with M8's app hosts, after M4's dark seams (Q-PHASE-1).

### 23.14 Interfaces

- **Provides:** 23.4-23.9's milestones M0-M10, v0 and v1, staffing, the gate map, freezes, lead times, gates, publication, merges and releases.
- **Consumes:** §2-§22's Phasing; §4.8; §11's format 2, the drop included, and its search index and remote search (11.14); §16.10's search tools and §16.11's directory; §19, its hardware (19.6), rota (19.8), triggers (19.9) and `format2` gate with its purge and drop modes (19.11); §22.8's schedules, D-TEST-11 to D-TEST-14 and D-TEST-18; §22.10's freezes; D-ARCH-4; D-SMTP-16 and -18.
- **Subprotocol messages, API routes, Tables, Services and config:** none.
- **Assumptions about other sections:** each Phasing uses 23.4's v0, v1 and M10; §22.8's FS rows carry 23.6's gates (FS-64 to FS-81, FS-83, FS-89 to FS-96, FS-107 to FS-112 and FS-125 at M10-out, FS-72's and FS-95's format-1 cases at M2-out, and later cases at the later of M10-out and M5-out (FS-66's, FS-69's, FS-76's, FS-78's and FS-92's hold cases), M6-out (FS-76's, FS-80's and FS-111's team-record cases, FS-83's team cases, FS-84's, FS-87's, FS-99's, FS-100's and FS-101's card and index cases, FS-86's card case, FS-88's search cases), M7-out (FS-76's, FS-78's, FS-111's and FS-112's mailbox cases) or M8-out (FS-77's, FS-83's, FS-109's, FS-110's and FS-125's app-host cases); FS-84, FS-85, FS-86, FS-87, FS-88, FS-99, FS-100 and FS-101's M6 cases at M6-out and FS-85's and FS-100's wakes at M8-out; FS-82's statement cases at M2-out, its mail cases at M7-out and its coverage cases at M8-out; FS-19's config read at M2-out with §8.19's ceiling, its grant and share runs at M4-out, its Team and invite runs at M6-out and its quick-burner run at M8-out; FS-21 at M4-out and on a Team default document at M6-out; FS-23 at M2-out and its mailbox case at M7-out; FS-30 at M3-out and its audit reader at M6-out; FS-38 at M4-out and its shares at M6-out with C18; FS-39's report intake at M5-out and the rest at M7-out; FS-41 and FS-42 at M3-out on M3's mechanisms and each later step at its mechanism's Gn-out, M5 to M9; FS-46 at M6-in; FS-47 at M2-out, its §21 case at M5-out and its mail case at M7-out; FS-63 at M2-out and on each next cluster; FS-106 at M2-out and its page Worker case at M4-out; FS-114 at M2-out and its purge and drop cases at M10-out; FS-116 to FS-118 at M2-out; FS-119 at M3-out and on each next cluster; FS-97 at M4-out and its Team cases at M6-out; FS-98 at M3-out, its Team cases at M6-out and its app-host cases at M8-out; FS-124 at M2-out, its CLI cases at M3-out, its Team cases at M6-out and its app-host cases at M8-out), §22.17 runs S7's SNI-less abuse@`<root>` case at M5, and §22.10's freeze evidence lists 23.6's schedules for its gate; §20.16 builds D-QUOTA-9's comparator and index at M4, the comparator gated off in main by §19.11's `escrow_draw_order` (D-OPS-10) until M6's Gn-out registers MG6's index, and §20.9 passes FS-46 and its benchmark on that build before M6's entry; §19.11 stages M2 on the production hosts and adds format 2's gate with its networks, percent, and purge and drop modes (each observe or on); §16.11 splits the directory between format 1's streams at M6 and cards, repo files and index at M10 (D-PHASE-11); RECORD.md and §16.18's v1 bring RS2's verifiable log and client packets (sidecar/design/pitch5.html:898) to M6.

### 23.15 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| §10.4's subset or its 0x0010 interop slips M2, as a required step tmc/mls lacks would, or the in-house MLS ships an unaudited flaw (owner decisions 43, 99) | Medium | Critical | started in M0 (D-PHASE-4); D-KEYS-10's interop artifact gates M2's exit (D-PHASE-7), OpenMLS's 0x004D as the second peer for such a step (§22.10); disclosed (owner decision 119) |
| File-cluster hardware arrives late | Medium | High | ordered in M0; M2's exit waits only for the hosts and their PM9A3 set (D-TEST-11), M3 for the rest |
| The next metadata cluster, or the new hosts later ones need, lands after a set passes 0.8 DWPD or fills, or a set sustains fewer pushes than §19.9 sizes it for; placed repos, which never move, outgrow their cluster (owner decision 145) | Medium | High | triggers projected over the lead time, hosts included (§19.9); §19.9 sizes the order from §22.8's measurements (D-OPS-17); the write budget sheds the heaviest network (§11.13); a move tool built before the earliest cohort exhaustion §19.9 projects, and until then its cohort limit (507 CLUSTER_FULL) |
| Year two's HDD load arrives before the segment placement and added HDD capacity: by §19.6's model its PUTs alone fill the 50% admission line | High by the model | High | §22.8's hdd run with admission on (M3); §19.9's hdd trigger orders both within their lead time; segment uploads refused heaviest network first meanwhile (§11.13) |
| Team B is not staffed by M2's exit | Medium | High | 23.5's fallback |
| The BDAT or DATA proof misses D-SMTP-16's bar (owner decision 125) | High | High | started in M0; BS1 launches receive-only |
| A Gn-out merge breaks the running release | Medium | High | R-PHASE-8; pending migrations (D-OPS-6; FS-54, FS-55); gates off by default (D-OPS-10) |
| From M6 until M8's wakes, an unwitnessed shared group stops writing at `witness_bound_hours` | Medium | Medium | agents witness; a 24 h alarm; the bound goes up to 168 h (owner decision 129) |
| Reader transfer, not NVMe, binds a 5,000-member Team's directory, and per-stream reads its M6 form | Medium | Medium | §16.11's policy (phones off the follow, 15-minute desktop syncs, reproduced heads, moved streams read 64 to a request); FS-86 gates §16.11's cost table at the Team limit from M6's exit, a miss going to the owner; a sharded cards ref if §22.8 binds |
| Senders without SNI defer; phone-only users, on iOS or Android, miss codes | High | High | the M7 census gates BS1; M8's mail indexer paths and prompt; the `foreground-only` copy before a first burner (owner decisions 12, 197) |
| Format 2 misses D-TEST-13 at 2× year one with the index on everywhere (owner decision 156), holding M10's freeze | Medium | High | 1 KiB blocks chosen at M2 on its projection (D-TEST-11); owner decision 172's companion cadence; the write budget sheds; the next cluster sooner (§19.9) |
| A purge, drop or migration bug destroys live content on production | Low | Critical | D-PHASE-10's and D-PHASE-12's staged rollouts, D-TEST-12's and D-TEST-18's soaks; FS-64 to FS-72 and FS-89 to FS-96 at M10-out |
| M10's engineers are not hired by M4's exit, and search lands after RS2 | Medium | Medium | 23.5's fallback, M10 after M6, which returns to the owner; no stage waits for it |
| No indexer is designated, so phones download all at "search more" (owner decision 177) | High | Low | owner decision 155's model; the app's indexer prompt names remote search; `ur indexer add --services search` |
| Format 2's computed write cost misses on production after the freeze | Medium | High | owner decision 174's accepted risk: §19.9's next cluster sooner (owner decision 145) or a later format change; the gate holds at internal networks and design partners meanwhile (D-TEST-13) |
| A rollback to format-1 binaries after format-2 data exists strands staged content | Low | High | FS-72's rollback case; format-2 batches left to a format-2 evacuator |
| A G0 re-check or the density review, running beside M0's bootstrap, finds something that changes what is already built (owner decision 193) | Medium | Medium | Findings return as Q- items (D-PHASE-2); the first format freeze is M2's (23.8), so a finding before it touches no frozen format |
| Later milestones build on formats that stay unfrozen, so a hardware miss, at D-TEST-11's run or later, forces rework in them (owner decision 194) | Medium | High | 23.8's freeze order still decides what reaches a production store (D-PHASE-7), and data on local, T3, canary and the staging cluster is rebuilt |

### 23.16 Phasing

23.6 is re-read at every Gn-in; work after M9 and M10, RS3 included, is 23.4's "Later"; M10's later cases are re-read at M5's, M6's, M7's and M8's Gn-in.
