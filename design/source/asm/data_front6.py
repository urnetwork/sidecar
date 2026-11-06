# Front matter and the "Owner decisions" section for DESIGN.md, sixth assembly (2026-11-04), written from the
# section files as last edited (2026-11-04 19:51), CONVENTIONS.md §0, §1 and §7, owner/APPLY.md (§2-§9),
# owner/DECISIONS.md (145 entries: 1-111 of 2026-11-03; 112-145 of 2026-11-04) and peer/orders/FRONT.md
# (FRONT-1 to FRONT-16, adapted where owner decisions 136-145, taken after the orders were written, govern).
# Loaded with runpy. "@@OD:N@@" marks a link to row N of the decisions-by-number table; assemble6.py resolves it.
# "@@NAME@@" placeholders are counts that assemble6.py computes from the section text.
import runpy, pathlib

_P3 = runpy.run_path(str(pathlib.Path(__file__).parent / 'data_front3.py'))
_P4 = runpy.run_path(str(pathlib.Path(__file__).parent / 'data_front4.py'))

TITLE = "# Sidecar infrastructure: technical design"

# The task's status line, verbatim.
STATUS = ("Status: draft for peer review, revised 2026-11-04 after the first peer review (see "
          "[DESIGN-REVIEW-RESPONSE.md](DESIGN-REVIEW-RESPONSE.md)). Nothing described here is implemented.")

SCOPE = _P3['SCOPE']

# FRONT-1: the Inbound mail bullet gains the platform listener's exception, worded as §2.8's statement now reads
# (headers and aggregate report data, D-SMTP-23). The quoted directive is unchanged.
_IN_OLD = ("- **Inbound mail (X6).** TLS terminates on a device or a customer-run sidecar, never at a URnetwork edge. "
           "The edge may see SNI, the connecting IP, the EHLO name and spam-relevant values; encrypt-on-receipt at the "
           "edge is ruled out.")
assert _IN_OLD in _P3['DIRECTIVE']
DIRECTIVE = _P3['DIRECTIVE'].replace(_IN_OLD, _IN_OLD + (
    " The one exception is `rpt.bringyour.com`'s report and role-mail listener, which terminates TLS to accept abuse "
    "reports and role mail, parses headers and aggregate report data only (D-SMTP-23), HPKE-seals the raw bytes to "
    "the network mail key (§14.8) and persists no plaintext (§15.4's mx-4; §2.8's statement and I-2 carry the same "
    "clause)."))

RULES = _P3['RULES']

BRANCH = """## Branch policy

All sidecar work happens on a branch named `sidecar` in every repo it touches (owner rule 4). Owner decisions 117 and 118 (2026-11-04) set the rest; §4.8, §23.9 and D-REPO-5 give the detail.

- **Public now, unscrubbed.** The sidecar repo is public from 2026-11-04 as it is, its documents and history included: no scrub, no archive, no filtered clone and no business-material allowlist (@@OD:117@@; D-REPO-8 is withdrawn). DESIGN.md and design-research/ join it on the `sidecar` branch (§4.11).
- **No private mirrors.** Every repo's `sidecar` branch uses that repo's normal remote, public where the repo is (@@OD:118@@; D-REPO-9 is withdrawn). The extension and app repos get one only if the owner opts in.
- **Branch starts** (§23.4): sidecar, connect, server, sdk, build, sn and xops in M0; mmm and config in M1; vault in M2; warp in M5.
- **Merge, never rebase.** `main` merges into every `sidecar` branch weekly and before each gate, in the order connect, sidecar, sdk, sn, server, warp/config/vault/xops/mmm, build, re-pinning the source-graph lock each time.
- **To `main` at every exit review.** At each milestone's exit review (Gn-out, §23.8), every touched repo, server and sdk included, merges `sidecar` into `main` in that order, connect's default-off changes first, once the pinned set passes its checks. Deploys, pilots and releases build from `main`, with features dark behind `config/<env>/sidecar.yml` (D-OPS-10). Each §19.7 migration group stays pending under the `sidecar_pending` build tag until its own milestone's Gn-out registers it (D-OPS-6), so one track's merge never applies the other's group and M3's pilot runs on production. Nothing waits for publication or for RS1 (D-PHASE-5 is withdrawn)."""

HOW = """## How to review

- **Where the decisions and questions are.** Every section follows one template: purpose and scope, requirements, what exists today, design, alternatives considered, decisions proposed, open questions, departures from PLAN.md, interfaces, risks and phasing. The [owner decisions](#owner-decisions) section below gives X1-X20, the [open owner questions](#open-owner-questions) (@@NQOWNWORD@@, raised while the sections were edited to the 2026-11-04 peer review), the items [closed by peer review](#closed-by-peer-review) and the [owner decisions by number](#owner-decisions-by-number). [Appendix A](#appendix-a-decision-register) lists all @@ND@@ D- items (@@NDW@@ withdrawn). [Appendix B](#appendix-b-open-questions-register) lists all @@NQ@@ Q- items: @@NQDEC@@ decided by the owner, @@NQPEERC@@ closed by peer review on 2026-11-04, @@NQOPEN@@ open for the owner, @@NQCLOSED@@ closed by the 2026-11-03 design-review round, which reviewers may reopen (§3.11), and @@NQW@@ withdrawn.
- **Id families.**
  - `X1`-`X20`: cross-cutting decisions. Each has one owning section, which resolves it in a Q- item whose text starts with the X id.
  - `R-CODE-n`: a requirement in section CODE's requirements table, with its source (a PLAN.md line, a product source, an owner decision, or "derived").
  - `D-CODE-n`: a proposed decision with its rationale (*Why:*), a decided one that names its owner decision, or a withdrawn one that names what superseded it.
  - `Q-CODE-n`: a question with options, a recommendation, what it blocks and its decider (owner or peer review). It is open, decided by the owner, closed by the design-review round, closed by peer review, or withdrawn; a decided item records the decision and any residual.
  - `I-1`..`I-18`: the security invariants of §2.9, binding on every section.
  - CODEs: CTX §1, TRUST §2, ARCH §3, REPO §4, CORE §5, PROTO §6, TEAM §7, ACL §8, SOCK §9, KEYS §10, EVS §11, DNS §12, TLS §13, SMTP §14, MAIL §15, MCP §16, BRIDGE §17, SDK §18, OPS §19, QUOTA §20, ABUSE §21, TEST §22, PHASE §23.
  - Other families: C1-C18 (connect changes, §4.6, Appendix E), F1-F10 (flows, §3.7), KF1-KF7 (MLS flows, §10.7), S1-S10 (test scenarios, §22.7), FI-1 to FI-14 (fault-schedule invariants, §22.8), FS-1 to FS-63 (fault schedules, §22.8), I-EVS-1 to I-EVS-7 (evs storage invariants, §11.8), P0-P2 (§11.13's write-budget classes; P0 is also the staged auth fix, §7.4), AD1-AD4, AU1-AU4 and TS1 (approval-decision, approval-use and taint invariants, §16.6), RV1-RV3 (restore invariants, §16.7), DP1 (the device posture invariant, §18.6), WK1-WK4 (wake invariants, §18.7), E-a to E-e (escrow draw invariants, §20.9), M0-M9 (milestones, §23.4), G0, Gn-in and Gn-out (review gates, §23.8), RS1-RS3 (recURd stages) and BS1 (the burner launch), W1-W11 (warp changes, §19.5), Y1-Y2 (load years, §19.6), MG0-MG9 (migration groups, §19.7), T1-T6 (test tiers, §22.4), TL1-TL4 (MX authentication levels, §14.4), E1-E3 and Z1-Z9 (preamble proof checks, §14.5) and π1-π3 (its proof parts), EX1-EX8 (operator capabilities, §2.8), TB1-TB3 (trust boundaries, §2.4), H1 and H3 (connect carriers), and the metadata rows of §2.8 (connect-1, api-7, evs-11, ...). An id after a `[R:key]` link, such as "§5 R8" or "S11", names an item inside that research sheet. No external review gates any milestone (@@OD:99@@).
- **Notation** (owner/APPLY.md §3; D-ARCH-1).
  - `<root>` is the user-content root, ur.network (@@OD:13@@). `<net>` is the network's opaque, immutable label (@@OD:14@@), or the opt-in alias where the user chose one. `<blabel>` is a burner's generated word-number label, so a burner address is `<name>@<blabel>.<net>.<root>` (@@OD:32@@).
  - Burners use a wildcard MX `*.<net>.<root> MX 10 mx.<net>.<root>`, a DANE TLSA record at `_25._tcp.mx.<net>.<root>` and SNI `mx.<net>.<root>`. A wildcard owner name carries no CNAME (RFC 1034 §3.6.2, RFC 2181 §10.1); wildcard A and AAAA records (the shared lb addresses) sit beside the wildcard MX, and a replying burner's label carries an explicit copy of them (D-DNS-11).
  - Platform and service names live on bringyour.com (@@OD:16@@). ur.io is the web; recURd runs at ur.io/recurd, and recurd.dev redirects there (@@OD:15@@).
  - The bridge overlay is a random IPv4 /16 per network, drawn from 100.64.0.0/10 by default, and a chosen block lies in 100.64.0.0/10 or RFC 1918 (@@OD:28@@, @@OD:132@@).
  - `<host>` is a zone-relative host. `<scope>` is a v1 Team scope sublabel for a member or tag (@@OD:40@@), whose hosts are `<label>.<scope>`. `<me>` appears only inside PLAN.md quotations.
- **Owner decisions.** "Owner decision N" cites entry N of the owner's record, owner/DECISIONS.md: entries 1-111 come from the interview of 2026-11-03; entries 112-125 from the follow-up of 2026-11-04, which answered the owner questions the fix rounds raised; entries 126-135 from that follow-up's second round, which answered those the conformance pass raised; entries 136-140 from the owner's evaluation of the storage tier; and entries 141-145 from the answers to the owner questions the 2026-11-04 peer review raised, all of 2026-11-04. Every such citation links to row N of [owner decisions by number](#owner-decisions-by-number), which gives the entry's date, states the decision in one line, notes supersession (owner/APPLY.md §2 and the later entries) and lists the sections that cite it. "Decided by owner 2026-11-03 (owner decision N)" or "Decided by owner 2026-11-04 (owner decision N)" marks a Q- item the owner settled; "implied by owner decision N" marks one that follows from it; "Closed by peer review 2026-11-04" marks one the peer review answered.
- **PLAN.md is the default.** PLAN.md statements are requirements unless a D- or Q- item says otherwise. Each section's "Departures from PLAN.md" lists its exceptions, and [Appendix F](#appendix-f-planmd-traceability) traces every PLAN.md line.
- **Source keys.** P5 = sidecar/design/pitch5.html, PM = sidecar/design/product.md, MK2 = sidecar/design/market2.md, FB = sidecar/FEEDBACK-SYSTEM.md, MM = sidecar/design/mocks/urnetwork-mobile.html, RA = sidecar/design/mocks/recurd-app.html, TM = sidecar/design/mocks/team-management.html, REC = sidecar/design/reports/Agent work record gaps and features.md, UI = cli/UI.md, EXT = connect/EXTENDERUPDATE.md, PLAN = sidecar/design/PLAN.md.
- **Citations.** Code is cited as `repo/path/file.go:LINE`, relative to the urnetwork checkout. `[R:key]` links a research fact sheet in [design-research/](design-research/) ([Appendix H](#appendix-h-research-sources)). "CONVENTIONS §0" is the owner directive above, "CONVENTIONS §1" the owner rules, and "CONVENTIONS §7" the X registry that the X1-X20 table replaces."""

# FRONT-5 and FRONT-6, adapted: owner decisions 141-145 answered the peer review's owner questions after FRONT.md
# was written, and Q-EVS-9 is the one owner question open now.
DECISIONS_INTRO = (
"The owner answered 111 questions on 2026-11-03, after the end-to-end-encryption directive, then on 2026-11-04 "
"14 more (entries 112-125) and 10 more (126-135), which settled every owner question that the fix rounds and the "
"conformance pass raised; 5 entries on the storage tier (136-140); and 5 more (141-145), which answered the five "
"owner questions that the 2026-11-04 peer review raised. That review closed the eleven Q- items left to it. One "
"owner question is open: Q-EVS-9, raised while the sections were edited to the review, listed below with its "
"recommendation, which the design follows until the owner answers. The sections are edited to these answers. Where "
"two answers disagree, owner/APPLY.md §2's supersession table and the later entries govern, and the table of "
"[owner decisions by number](#owner-decisions-by-number) notes each case. The assembly's checks (decision citations, "
"item status, residuals, and a grep for superseded options and for decided questions that still read as open) found "
"no section text that contradicts a decision, except where a decision's own clauses conflict, as owner decision "
"114's read-at-once and reap revocation do for Delegation-admitted agents, which §10.5 states as a residual, and "
"where two decisions meet: owner decision 140's ~10-15 KiB of drive writes a push lies below the ~14 KiB that owner "
"decision 2's head overwrite alone writes, which Q-EVS-9 puts to the owner. This section lists the cross-cutting "
"decisions, the open owner questions, what peer review closed, and every decision with the sections that implement it."
)

X_INTRO = (
"X1-X20 are the cross-cutting decisions the research surfaced (CONVENTIONS §7). Each row is built from its owning "
"section's `[Xn]` Q- item: its question, the decision with the owner decisions that settle it, and its residual "
"as the item states it. Every X item is decided; the one open owner question, Q-EVS-9, concerns X13's write budget."
)

_X4 = {r[0]: r for r in _P4['X_ROWS']}
X_ROWS = [
("X1", _X4['X1'][1],
 "TLS ends in the listening sidecar (the directive), reached through 13.4's `ssl_preread` SNI split on the shared lb addresses (@@OD:34@@). certs' CSR proxy in URnetwork zones and the customer's own CAA-pinned account on Team custom domains, which excludes URnetwork only in strong mode (@@OD:39@@); per-device keys and certificates plus scope sublabels, never a shared key (@@OD:40@@); 13.9's abuse hooks plus a verified account before any Community publish (@@OD:41@@).",
 "§13", "Q-TLS-1 (with Q-TLS-2, Q-TLS-3, Q-TLS-4)", "None."),
("X2", _X4['X2'][1],
 "Keyed path tokens in an object index, token-prefix subscriptions, path-key rotation on member removal, and all storage state as objects (11.5-11.8; @@OD:2@@).",
 "§11", "Q-EVS-1", "None; Q-EVS-6 was closed by peer review 2026-11-04."),
_X4['X3'], _X4['X4'], _X4['X5'],
("X6", _X4['X6'][1],
 "Inbound TLS ends on customer receivers (the directive); mxedge routes by SNI alone with DANE TLSA, and senders without SNI defer (@@OD:31@@, @@OD:34@@). Always-on receivers plus the iOS app in the foreground, which is no reliable receiver (@@OD:12@@); burners `<name>@<blabel>.<net>.<root>` under the wildcard MX (@@OD:32@@, superseding @@OD:29@@); plaintext senders refused with 530 and a published deviation, plus a Team direct MX (@@OD:33@@).",
 "§15", "Q-MAIL-1 (with Q-MAIL-2, Q-MAIL-3, Q-MAIL-9)", _X4['X6'][5]),
("X7", _X4['X7'][1],
 "Nothing ships until 14.5's proofs pass D-SMTP-16's gate, with no external audit, and burner email launches receive-only (@@OD:35@@, @@OD:99@@); a DATA circuit is always funded, built beside BDAT and part of the gate (@@OD:125@@; D-SMTP-20): DATA proves at most the host's `smtp_data_proof_bytes` in 2 h, so larger mail to an MX without CHUNKING gets a DSN, and both modes prove the MX's replies (D-SMTP-22). An unauthenticated MX is refused with a DSN unless the user allows the domain (@@OD:38@@); each sending sidecar holds its own DKIM key under an opaque selector, at most 64 (@@OD:36@@).",
 "§14", "Q-SMTP-1 (with Q-SMTP-4, Q-SMTP-5)", "None."),
_X4['X8'],
("X9", _X4['X9'][1], _X4['X9'][2], "§4", "Q-REPO-2", "C17, for the extension's streaming Worker only, after §18's spike."),
_X4['X10'], _X4['X11'],
("X12", _X4['X12'][1],
 "MLS in v0 (@@OD:1@@), built in house as 10.4's subset, its audit deferred (@@OD:43@@, @@OD:99@@), on ciphersuite 0x0010 (@@OD:44@@), one group per evs repo whose leaves are member devices while agents hold wraps (@@OD:60@@, @@OD:114@@). GKM is a delivery service plus wrapped, laddered generations in the file cluster (implied by @@OD:59@@), and gkm sees 10.6's rows: ciphertext, group id, epoch, sizes and sidecar ids, never, in a member commit, a proposal, credential change, tree or key, external commits showing gkm-6's values (@@OD:115@@).",
 "§10", "Q-KEYS-9 (with Q-KEYS-1, -2, -3, -4, -12)", "None."),
("X13", _X4['X13'][1],
 "(a) 19.6's MinIO clusters at one site, built from the final upstream source and ordered by the store's conditional writes, with no off-site copy (@@OD:18@@, @@OD:20@@, @@OD:21@@, @@OD:94@@; ordering @@OD:2@@): an HDD segment cluster at EC:8 and a metadata cluster of 8 × PM9A3 1.92 TB at EC:4 with a cold spare (owner decisions 116, 136-139), under a write budget of 0.8 DWPD and 50% of rated IOPS (@@OD:140@@), Redis holding only soft state (@@OD:136@@), the metadata tier growing only by whole clusters, each repo placed at creation (@@OD:145@@); the load inputs stay an engineering estimate (@@OD:116@@).",
 "§19 (with §11)", "Q-OPS-1", "None in the item; Q-EVS-9 (open, owner) asks whether @@OD:140@@'s ~10-15 KiB a push binds."),
("X14", _X4['X14'][1], _X4['X14'][2], "§18", "Q-SDK-1",
 "18.10's size spike, which decides C17 for the extension's streaming Worker only (@@OD:22@@); pages use the `sidecar_http` leg (D-SDK-19)."),
_X4['X15'],
("X16", _X4['X16'][1],
 "(b) PLAN's quotas and 20.4's Team price ($100 a month for 5 billable seats, then $20 a seat), overage only on transfer and storage, replies-only dropped (@@OD:27@@); overage at existing rates: transfer at the data-pack rate ($3 per TiB) and storage per GiB-month from §19.6's cost per usable TB of the decided hardware (owner decisions 136-139), reviewed yearly, so storage counts in GiB (@@OD:122@@).",
 "§20", "Q-QUOTA-1", "None."),
_X4['X17'], _X4['X18'], _X4['X19'], _X4['X20'],
]
assert [r[0] for r in X_ROWS] == [f"X{i}" for i in range(1, 21)]

OPEN_INTRO = (
"One, Q-EVS-9, raised while the sections were edited to the 2026-11-04 peer review; owner decisions 136-145 answered "
"the storage-tier evaluation and the five questions that review raised (Q-EVS-8, Q-MCP-6, Q-OPS-9, Q-KEYS-15, "
"Q-OPS-10), and owner decisions 112-135 every earlier owner question. Until the owner answers, the design follows "
"the recommendation, which blocks nothing before §22.8's M2 drive-write run, and format 1's byte freeze uses its gate "
"(D-TEST-11). §1.9, §3.1 and §23.6 still say that no owner question is open, and §23.6's map does not yet place "
"Q-EVS-9. Outside the Q- items, the owner keeps one launch call on measured data: accepting the SNI loss that M7's "
"census measures, before BS1 (D-MAIL-9; @@OD:34@@; §23.6)."
)
# Q id | question | options | recommendation | blocks | needed by (FRONT-7's columns)
OPEN_OWNER = [
("Q-EVS-9",
 "Must the design meet owner decision 140's ~10-15 KiB of drive writes a push, when owner decision 2's commit point, the head's If-Match overwrite, alone writes ~14 KiB a drive (~10.5 on 1 KiB blocks), since MinIO also rewrites the old xl.meta? The design lands at ~27-43 KiB a push and meets the binding 0.8 DWPD and 50%-of-rated-IOPS limits at the per-set capacity owner decision 145 accepted.",
 "(a) take the binding limits as the target, with §22.8's 43 KiB gate (D-TEST-11); (b) a head per version created If-None-Match, ~5 KiB less a push, departing from owner decision 2's If-Match commit point; (c) patch MinIO to skip the old xl.meta's copy on overwrite, ~4 KiB less, giving up its torn-write backup",
 "(a)", "nothing before §22.8's M2 drive-write run; format 1's byte freeze uses (a)'s gate", "M2 (exit)"),
]

# FRONT-8 and FRONT-9: "Left to peer review" becomes "Closed by peer review". Each answer is checked against the
# current section text; Q-OPS-2's follows the section and owner decision 136 (history leaves the batches after 24 h,
# gen/ unpacked), not FRONT-9's "weekly" and "gen/ before Y2", and Q-KEYS-11's adds its residual.
PEER_INTRO = (
"No Q- item is open for peer review. The items whose decider was peer review were closed on 2026-11-04; each now "
"reads “Closed by peer review 2026-11-04” in its section, with its answer, and §23.6 lists what each still gates. "
"Decided items leave one engineering residual: Q-SDK-1's size spike, which decides C17 (Q-REPO-2). The items the "
"2026-11-03 design-review round closed ([Appendix B](#appendix-b-open-questions-register)) were not closed by human "
"peer review, and reviewers may reopen them (§3.11)."
)
_PQ = {r[0]: r for r in _P4['PEER']}
# Q id | question | closed by peer review 2026-11-04 | needed by
PEER = [
("Q-TEST-1", _PQ['Q-TEST-1'][1], "(a): `sidecartest` builds on connect's exported API, and T3 reruns each fake-backed scenario on server's exchange", _PQ['Q-TEST-1'][4]),
("Q-TEST-2", _PQ['Q-TEST-2'][1], "(a) and (b): a 3-master Redis Cluster and erasure-coded MinIO locally, in T3 and at the release gate, plus a CROSSSLOT lint", _PQ['Q-TEST-2'][4]),
("Q-CORE-4", _PQ['Q-CORE-4'][1], "(b) in v0: a DPoP proof by the ClientKey on strict-expiry refresh, token exchange and auth-client; (c) later", _PQ['Q-CORE-4'][4]),
("Q-TEST-6", _PQ['Q-TEST-6'][1], "(b): no `oneof` in envelope, stream or push messages or what they carry, by a descriptor lint", _PQ['Q-TEST-6'][4]),
("Q-CTX-4", _PQ['Q-CTX-4'][1], "(a): §9's blinded `share/<token>` socket while `ur share` runs (D-SOCK-16)", _PQ['Q-CTX-4'][4]),
("Q-KEYS-11", _PQ['Q-KEYS-11'][1], "(a): 30 days, then until recent ackers have applied them; never the newest epoch; §19.9 sizes the family at M2's benchmark", _PQ['Q-KEYS-11'][4]),
("Q-EVS-6", _PQ['Q-EVS-6'][1], "(c), made cheap: head readers replay signed statements of at most 1 KiB from their pin", _PQ['Q-EVS-6'][4]),
("Q-OPS-2", "Should small objects pack? Y2's HDD mix needs ~32,000 drive operations a second against ~8,000-12,800 (19.6).",
 "(b) in v0, with content-id addressing reserved so packing small segments is a switch, turned on once HDD drive operations pass 50% of measured capacity; history leaves the batches after 24 h (owner decision 136); `gen/` stays unpacked", _PQ['Q-OPS-2'][4]),
("Q-BRIDGE-2", _PQ['Q-BRIDGE-2'][1], "(c): a fixed client per target with a WindowDelegation per window client; own-client links once measured", _PQ['Q-BRIDGE-2'][4]),
("Q-SDK-5", _PQ['Q-SDK-5'][1], "(b): the leaf package `sidecar/device` over `protocol/bridge` (D-SDK-20)", _PQ['Q-SDK-5'][4]),
("Q-OPS-5", _PQ['Q-OPS-5'][1], "(a): staged, N and N+1 compatible, with stop rules and a rollback drill", _PQ['Q-OPS-5'][4]),
]

INDEX_INTRO = (
"Every entry of the owner's record (owner/DECISIONS.md), by number: 1-111 from the interview of 2026-11-03; 112-125 "
"from the follow-up of 2026-11-04, 126-135 from its second round, 136-140 on the storage tier and 141-145 answering "
"the peer review's owner questions, all of 2026-11-04. \"Settles\" names the X and Q- items the entry decides. The "
"decision is one line, faithful to the record; where owner/APPLY.md §2 or a later entry supersedes, amends or "
"confirms an entry, the line says so. \"Implemented in\" lists the sections whose text cites the entry as \"owner "
"decision N\"; a summary range such as `owner decisions 1-145` does not count as citing each entry."
)

# Rows 1-135 start from the fourth assembly's (data_front4.py), with the notes that entries 136-145 add.
_UPD = {
2: (None, "Hashed path segments: keyed, parent-chained 16-byte tokens; under the final owner direction, evs and gkm are stateless over file-cluster objects (seg/, idx/, head/, push/, subs/, gkm/), with no Postgres or Redis for file storage. The earlier Postgres path index and per-ref Postgres row are superseded; item 9's path-key rotation is read together with @@OD:64@@'s lazy rewrap. Owner decision 136 keeps this for durable state but moves the `subs/` leases and other soft state to Redis; @@OD:141@@ narrows its disjoint landing to file-mode refs."),
20: (None, "The file cluster is 4 hosts, each with 16 × 16 TB HDDs (about 1 PB raw); @@OD:94@@ sets the topology, @@OD:116@@ the parity, and owner decisions 136-139 each host's two NVMe drives."),
21: (None, "A small NVMe metadata tier, 2 drives per host, run as a separate pool or cluster with its own bucket, holds index entries, heads, push logs, gkm objects and subscriptions; @@OD:116@@ moved week-old push logs onto the HDDs, which @@OD:136@@ makes 24 h while moving subscriptions to Redis, owner decisions 138 and 139 set its drives (PM9A3), and @@OD:145@@ grows it only by whole clusters, never pools."),
24: (None, "A local git server (http and ssh) plus `git-remote-ur`; only the sidecar talks to evs. Its \"loopback only\" is superseded by @@OD:84@@; @@OD:130@@ makes the listener TLS-only beyond loopback, and @@OD:141@@'s tip CAS keeps git-mode refs git-compatible."),
60: (None, "One MLS group per evs repo; reader and writer grants map onto group membership. Amended by @@OD:114@@: member devices are leaves, and agents hold wraps; @@OD:144@@ adds member devices past a network's first 1,000, which read the config group by wraps."),
75: (None, "For single-device users, the harness's permission prompt counts as approval, labeled by evidence type; in a tainted run @@OD:142@@ counts it only where a `requests` rule names it."),
89: (None, "v0 runs at one site: RPO 5 min for metadata and 1 h for segments, RTO 4 h, for drive and host failures only (@@OD:94@@), which also supersedes its off-site replication; a second site is decided from operating data. Owner decision 143's rota holds the RTO at all hours."),
94: (None, "v0 has one site, one metadata and one storage cluster, \"2 replicas\" read as 50% parity, and no off-site copy; it supersedes the off-site parts of @@OD:18@@ and @@OD:89@@; @@OD:116@@ confirms the parity reading, and @@OD:145@@ grows the metadata tier by whole clusters."),
95: (None, "Automated abuse actions act at once, with human review within 24 h; business-hours staff in v0, 24/7 on-call by v1; @@OD:134@@ adds an emergency pager from M5, which @@OD:143@@'s infrastructure rota carries."),
114: (None, "Tagged, ephemeral, CI and cloud sidecars read and write through per-generation X-Wing wraps, not MLS leaves, amending @@OD:60@@; agents read once a grant exists and leave the 1,000 leaves to members; wrapped writers rotate but never commit Removes, and revoking an agent is a generation not wrapped to it. Owner decision 144 amends its \"member devices are leaves\" for the config group."),
116: (None, "The file cluster as recommended: EC:8 on the HDD sets (about 512 TB usable) and EC:4 on the NVMe tier, 3.84 TB NVMe drives with a pool before Y2, week-old push logs packed onto HDD (refining @@OD:21@@), a cold spare on site; the Y1 and Y2 inputs stay an estimate. Its drives are superseded by owner decisions 136 and 138 (8 × PM9A3 1.92 TB), its week by @@OD:136@@'s 24 h, and its pool by @@OD:145@@."),
122: (None, "Overage uses existing rates: transfer at the data-pack rate ($3/TiB) and storage per GiB-month from the cluster's cost per usable TB, reviewed yearly, with prices in pro.yml; owner decisions 136-139 set the hardware behind that cost."),
128: (None, "In the config repo's MLS group, the leaf that signed an admission or revocation commits the MLS change it requires, even if not a config writer; recovery-admitted devices self-join by external commit; writing config records stays admin-only. Extends @@OD:113@@; @@OD:144@@ asks how it applies when the signer holds a config wrap."),
134: (None, "Business-hours review with automated actions holding until reviewed (@@OD:95@@), plus an on-call pager from M5 only for registrar, registry and law-enforcement emergency notices, EU removal orders included; 24/7 on-call in v1. Its notices join @@OD:143@@'s rota at M5."),
}
INDEX = []
for (_n, _settles, _dec) in _P4['INDEX']:
    if _n in _UPD:
        _s, _d = _UPD[_n]
        INDEX.append((_n, _s or _settles, _d))
    else:
        INDEX.append((_n, _settles, _dec))
INDEX += [
(136, "Q-OPS-1 (X13): the NVMe tier", "The metadata tier is 2 × 2 TB NVMe per host (one 8-drive set, ~8 TB usable at EC:4) beside the unchanged HDD cluster; MinIO stays the system of record and Redis holds only soft state (subscription leases, a verified head and projection cache); history packs daily once older than 24 h, at 7 days under 256 KiB; XFS with `maxpct=25`; a second pool at 50% raw, 40% inodes or 0.5 DWPD. Supersedes @@OD:116@@'s 3.84 TB drives and week; its drives are refined by owner decisions 137 and 138, and its second pool is superseded by @@OD:145@@."),
(137, "Q-OPS-1 (X13): the drive model", "The metadata drives are 8 × Samsung PM963 1.92 TB M.2 22110 (15.4 TB raw, ~7.7 TB usable), SMART-checked before use, with §22.8's M2 benchmark on them comparing 4 KiB and 1 KiB XFS blocks, and small-object counts a first-class budget. Its model is superseded for the initial cluster by @@OD:138@@; @@OD:139@@ leaves the PM963 out of the initial deployment."),
(138, "Q-OPS-1 (X13): the initial drives", "The initial metadata set is 8 × Samsung PM9A3 1.92 TB M.2 22110 (PCIe 4.0 x4, ~800k random-read and ~85k random-write IOPS, 1 DWPD, power-loss protection), 2 per host, 15.4 TB raw and ~7.7 TB usable at EC:4, every set homogeneous with PM9A3 spares; supersedes @@OD:137@@'s model. Its later PM963 pool is superseded by @@OD:139@@, and its pool-and-rebalance expansion by @@OD:145@@."),
(139, "Q-OPS-1 (X13): the initial deployment", "The initial deployment is PM9A3 only: 8 drives in the set, 2 per host, plus 2-4 PM9A3 cold spares, no PM963; a later set's model is chosen when its trigger fires, as its own cluster under @@OD:145@@."),
(140, "Q-OPS-1 (X13): the write budget", "The design must fit the 8 × PM9A3 set as a hard budget: at most 0.8 DWPD and 50% of rated IOPS at the design load, reads preferred to writes, about 10-15 KiB of drive writes a push, and a global NVMe write budget from drive telemetry enforced by §11.13's shedder, which §22.8's M2 benchmark gates format 1 on. Q-EVS-9 (open) asks whether the 10-15 KiB target binds, given @@OD:2@@'s head overwrite."),
(141, "Q-EVS-8", "Git-mode refs commit only on their tip (a tip CAS; a loser pulls or merges) and file-mode refs keep @@OD:2@@'s disjoint landing, narrowing it to file-mode refs so that git compatibility (@@OD:24@@) and exact git oids hold; D-EVS-22 is decided."),
(142, "Q-MCP-6", "In a tainted run (I-9), harness evidence approves an outward action only where the matching `requests` rule names it, never through `evidenceDefault`; otherwise approval needs second-device or presence-key evidence. Untainted runs keep @@OD:75@@'s fallback."),
(143, "Q-OPS-9", "A two-person out-of-hours infrastructure rota on one pager service from M3, with 30-minute acknowledgment and escalation, for page-class alerts only; @@OD:134@@'s notices join it at M5, so the 4 h RTO (owner decisions 89, 116) and §19.8's SLOs hold at all hours."),
(144, "Q-KEYS-15", "Member devices past a network's first 1,000 read the config group by per-generation wraps from the start, as agents do, and stay leaves of their data repos (each still at most 1,000), with no member-device cap; it amends @@OD:114@@ for the config group only, and wrapped member devices commit no config-group Removes."),
(145, "Q-OPS-10", "The metadata tier grows only by adding metadata clusters, never MinIO pools: each new repo and its gkm group are placed at creation by a create-only `place/<repo_id>` on the first cluster, and all their objects stay there; a move tool is later. Supersedes @@OD:136@@'s second pool; the triggers stay."),
]
DATES = {n: ('2026-11-03' if n <= 111 else '2026-11-04') for n in range(1, 146)}

# Known gaps: section text that still contradicts an owner decision (where, text, decision, note). Filled from
# validation; empty when none is found.
KNOWN_GAPS_INTRO = ("The assembly's checks found section text that still contradicts an owner decision. Each row names "
                    "the place, the text and the decision that governs; each needs a section edit.")
KNOWN_GAPS = []
