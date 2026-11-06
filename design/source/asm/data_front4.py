# Front matter and the "Owner decisions" section for DESIGN.md, fourth assembly (2026-11-04), written from the section
# files as last edited (2026-11-04 10:48), CONVENTIONS.md §0, §1 and §7, owner/APPLY.md (§2-§7) and owner/DECISIONS.md
# (135 entries: 1-111 of 2026-11-03; 112-125 and 126-135 of 2026-11-04). Loaded with runpy.
# "@@OD:N@@" marks a link to row N of the decisions-by-number table; assemble4.py resolves it.
# "@@NAME@@" placeholders are counts that assemble4.py computes from the section text.
import re, runpy, pathlib

_P3 = runpy.run_path(str(pathlib.Path(__file__).parent / 'data_front3.py'))

TITLE = "# Sidecar infrastructure: technical design"

STATUS = ("Status: draft for peer review, 2026-11-04. Nothing described here is implemented. "
          "The owner's design decisions of 2026-11-03 and 2026-11-04 are applied throughout; "
          "every remaining open question is for peer review.")

SCOPE = _P3['SCOPE']

DIRECTIVE = _P3['DIRECTIVE']

RULES = _P3['RULES']

BRANCH = """## Branch policy

All sidecar work happens on a branch named `sidecar` in every repo it touches (owner rule 4). Owner decisions 117 and 118 (2026-11-04) set the rest; §4.8, §23.9 and D-REPO-5 give the detail.

- **Public now, unscrubbed.** The sidecar repo is public from 2026-11-04 as it is, its documents and history included: no scrub, no archive, no filtered clone and no business-material allowlist (@@OD:117@@; D-REPO-8 is withdrawn). DESIGN.md and design-research/ join it on the `sidecar` branch (§4.11).
- **No private mirrors.** Every repo's `sidecar` branch uses that repo's normal remote, public where the repo is (@@OD:118@@; D-REPO-9 is withdrawn). The extension and app repos get one only if the owner opts in.
- **Branch starts** (§23.4): sidecar, connect, server, sdk, build and sn in M0; mmm in M1; config, vault and xops in M2; warp in M5.
- **Merge, never rebase.** `main` merges into every `sidecar` branch weekly and before each gate, in the order connect, sidecar, sdk, sn, server, warp/config/vault/xops/mmm, build, re-pinning the source-graph lock each time.
- **To `main` at every exit review.** At each milestone's exit review (Gn-out, §23.8), every touched repo, server and sdk included, merges `sidecar` into `main` in that order, connect's default-off changes first, once the pinned set passes its checks. Deploys, pilots and releases build from `main`, with features dark behind `config/<env>/sidecar.yml` (D-OPS-10). Each §19.7 migration group's SQL merges with its milestone's code at the Gn-out whose deploy first applies it, so M3's pilot runs on production. Nothing waits for publication or for RS1 (D-PHASE-5 is withdrawn)."""

HOW = """## How to review

- **Where the decisions and questions are.** Every section follows one template: purpose and scope, requirements, what exists today, design, alternatives considered, decisions proposed, open questions, departures from PLAN.md, interfaces, risks and phasing. The [owner decisions](#owner-decisions) section below gives X1-X20, the [open owner questions](#open-owner-questions) (none remain), the items [left to peer review](#left-to-peer-review) and the [owner decisions by number](#owner-decisions-by-number). [Appendix A](#appendix-a-decision-register) lists all @@ND@@ D- items (@@NDW@@ withdrawn). [Appendix B](#appendix-b-open-questions-register) lists all @@NQ@@ Q- items: @@NQDEC@@ decided by the owner, @@NQOPEN@@ open, every one for peer review, @@NQCLOSED@@ closed by the 2026-11-03 design-review round, which reviewers may reopen (§3.11), and @@NQW@@ withdrawn.
- **Id families.**
  - `X1`-`X20`: cross-cutting decisions. Each has one owning section, which resolves it in a Q- item whose text starts with the X id.
  - `R-CODE-n`: a requirement in section CODE's requirements table, with its source (a PLAN.md line, a product source, an owner decision, or "derived").
  - `D-CODE-n`: a proposed decision with its rationale (*Why:*), or a withdrawn one that names what superseded it.
  - `Q-CODE-n`: a question with options, a recommendation, what it blocks and its decider (owner or peer review). It is open, decided by the owner, closed by the design-review round, or withdrawn; a decided item records the decision and any residual.
  - `I-1`..`I-18`: the security invariants of §2.9, binding on every section.
  - CODEs: CTX §1, TRUST §2, ARCH §3, REPO §4, CORE §5, PROTO §6, TEAM §7, ACL §8, SOCK §9, KEYS §10, EVS §11, DNS §12, TLS §13, SMTP §14, MAIL §15, MCP §16, BRIDGE §17, SDK §18, OPS §19, QUOTA §20, ABUSE §21, TEST §22, PHASE §23.
  - Other families: C1-C18 (connect changes, §4.6, Appendix E), F1-F10 (flows, §3.7), KF1-KF7 (MLS flows, §10.7), S1-S10 (test scenarios, §22.7), M0-M9 (milestones, §23.4), G0, Gn-in and Gn-out (review gates, §23.8), RS1-RS3 (recURd stages) and BS1 (the burner launch), W1-W11 (warp changes, §19.5), Y1-Y2 (load years, §19.6), MG0-MG9 (migration groups, §19.7), T1-T6 (test tiers, §22.4), TL1-TL4 (MX authentication levels, §14.4), E1-E3 and Z1-Z6 (preamble proof checks, §14.5), EX1-EX8 (operator capabilities, §2.8), P0 (the staged auth fix, §7.4), TB1-TB3 (trust boundaries, §2.4), H1 and H3 (connect carriers), and the metadata rows of §2.8 and Appendix G (connect-1, api-7, evs-11, ...). An id after a `[R:key]` link, such as "§5 R8" or "S11", names an item inside that research sheet. No external review gates any milestone (@@OD:99@@).
- **Notation** (owner/APPLY.md §3; D-ARCH-1).
  - `<root>` is the user-content root, ur.network (@@OD:13@@). `<net>` is the network's opaque, immutable label (@@OD:14@@), or the opt-in alias where the user chose one. `<blabel>` is a burner's generated word-number label, so a burner address is `<name>@<blabel>.<net>.<root>` (@@OD:32@@).
  - Burners use a wildcard MX `*.<net>.<root> MX 10 mx.<net>.<root>`, a DANE TLSA record at `_25._tcp.mx.<net>.<root>` and SNI `mx.<net>.<root>`. A wildcard owner name carries no CNAME (RFC 1034 §3.6.2, RFC 2181 §10.1); wildcard A and AAAA records (the shared lb addresses) sit beside the wildcard MX.
  - Platform and service names live on bringyour.com (@@OD:16@@). ur.io is the web; recURd runs at ur.io/recurd, and recurd.dev redirects there (@@OD:15@@).
  - The bridge overlay is a random IPv4 /16 per network, drawn from 100.64.0.0/10 by default, and a chosen block lies in 100.64.0.0/10 or RFC 1918 (@@OD:28@@, @@OD:132@@).
  - `<host>` is a zone-relative host. `<scope>` is a v1 Team scope sublabel for a member or tag (@@OD:40@@), whose hosts are `<label>.<scope>`. `<me>` appears only inside PLAN.md quotations.
- **Owner decisions.** "Owner decision N" cites entry N of the owner's record, owner/DECISIONS.md: entries 1-111 come from the interview of 2026-11-03; entries 112-125 from the follow-up of 2026-11-04, which answered the owner questions the fix rounds raised; and entries 126-135 from that follow-up's second round, which answered those the conformance pass raised. Every such citation links to row N of [owner decisions by number](#owner-decisions-by-number), which gives the entry's date, states the decision in one line, notes supersession (owner/APPLY.md §2 and the later entries) and lists the sections that cite it. "Decided by owner 2026-11-03 (owner decision N)" or "Decided by owner 2026-11-04 (owner decision N)" marks a Q- item the owner settled; "implied by owner decision N" marks one that follows from it.
- **PLAN.md is the default.** PLAN.md statements are requirements unless a D- or Q- item says otherwise. Each section's "Departures from PLAN.md" lists its exceptions, and [Appendix F](#appendix-f-planmd-traceability) traces every PLAN.md line.
- **Source keys.** P5 = sidecar/design/pitch5.html, PM = sidecar/design/product.md, MK2 = sidecar/design/market2.md, FB = sidecar/FEEDBACK-SYSTEM.md, MM = sidecar/design/mocks/urnetwork-mobile.html, RA = sidecar/design/mocks/recurd-app.html, TM = sidecar/design/mocks/team-management.html, REC = sidecar/design/reports/Agent work record gaps and features.md, UI = cli/UI.md, EXT = connect/EXTENDERUPDATE.md, PLAN = sidecar/design/PLAN.md.
- **Citations.** Code is cited as `repo/path/file.go:LINE`, relative to the urnetwork checkout. `[R:key]` links a research fact sheet in [design-research/](design-research/) ([Appendix H](#appendix-h-research-sources)). "CONVENTIONS §0" is the owner directive above, "CONVENTIONS §1" the owner rules, and "CONVENTIONS §7" the X registry that the X1-X20 table replaces."""

DECISIONS_INTRO = (
"The owner answered 111 questions on 2026-11-03, after the end-to-end-encryption directive, then 14 more (entries "
"112-125) and 10 more (entries 126-135) on 2026-11-04, which settled every owner question that the fix rounds and the "
"conformance pass raised. No question for the owner remains open; the open Q- items are left to peer review. The "
"sections are edited to these answers. Where two answers disagree, owner/APPLY.md §2's supersession table and the later "
"entries govern, and the table of [owner decisions by number](#owner-decisions-by-number) notes each case. The "
"assembly's checks (decision citations, item status, residuals, and a grep for superseded options and for decided "
"questions that still read as open) found no section text that contradicts a decision. This section lists the "
"cross-cutting decisions, the open owner questions, what is left to peer review, and every decision with the sections "
"that implement it."
)

X_INTRO = (
"X1-X20 are the cross-cutting decisions the research surfaced (CONVENTIONS §7). Each row is built from its owning "
"section's `[Xn]` Q- item: its question, the decision with the owner decisions that settle it, and its residual "
"as the item states it. Every X item is decided, and no residual waits for the owner."
)

# X | question | decision | owning § | Q id | residual
X_ROWS = [
("X1", "Where does TLS end, and how does TCP 443 split? Who orders certificates for device-held keys, how do a team's devices share the wildcard, and is abuse handling without inspection enough?",
 "TLS ends in the listening sidecar (the directive), reached through 13.4's `ssl_preread` SNI split on the shared lb addresses (@@OD:34@@). certs' CSR proxy in URnetwork zones and the customer's own CAA-pinned account on Team custom domains (@@OD:39@@); per-device keys and certificates plus scope sublabels, never a shared key (@@OD:40@@); 13.9's abuse hooks plus a verified account before any Community publish (@@OD:41@@).",
 "§13", "Q-TLS-1 (with Q-TLS-2, Q-TLS-3, Q-TLS-4)", "None."),
("X2", "Which header values may evs see, and how do head reads and subpath subscriptions work without plaintext paths?",
 "Keyed path tokens in an object index, token-prefix subscriptions, path-key rotation on member removal, and all storage state as objects in the file cluster (11.5-11.8; @@OD:2@@).",
 "§11", "Q-EVS-1", "Q-EVS-6 (peer review): must a head reader that does not replay verify per-file freshness?"),
("X3", "Who is the policy authority?",
 "A customer key authority from v0, compiled on customers' devices, in the encrypted config repo (§7.9, §8.7); servers enforce its signed id-only projection (owner decisions 3, 5-8 and 110). Q-TRUST-1, Q-TEAM-5 and Q-KEYS-5 follow.",
 "§8 (with §7)", "Q-ACL-1", "None."),
("X4", "Which registrable domain carries user names?",
 "(b1) ur.network for user content only: signed, strict DMARC, PSL-listed when eligible (§12.4; @@OD:13@@); platform names on bringyour.com (@@OD:16@@).",
 "§12", "Q-DNS-1", "None."),
("X5", "What is a network's label?",
 "(a) opaque, random and immutable, with an opt-in alias equal to network_name (§12.5; @@OD:14@@).",
 "§12", "Q-DNS-2", "None."),
("X6", "How does mxedge route inbound mail without terminating TLS? Which devices receive, what is the burner format, and are senders without STARTTLS refused?",
 "Inbound TLS ends on customer receivers (the directive); mxedge routes by SNI alone with DANE TLSA, and senders without SNI defer (@@OD:31@@, @@OD:34@@). Always-on receivers plus the iOS app in the foreground (@@OD:12@@); burners `<name>@<blabel>.<net>.<root>` under the wildcard MX (@@OD:32@@, superseding @@OD:29@@); plaintext senders refused with 530 and a published deviation, plus a Team direct MX (@@OD:33@@).",
 "§15", "Q-MAIL-1 (with Q-MAIL-2, Q-MAIL-3, Q-MAIL-9)", "None. Outside the Q- items, BS1 waits for the owner to accept the SNI loss that D-MAIL-9's M7 census measures (§23.6)."),
("X7", "How is the preamble made trustworthy, and what ships before a sound proof? What happens to an unauthenticated MX, and who holds DKIM keys?",
 "Nothing ships until 14.5's proofs pass D-SMTP-16's gate, with no external audit, and burner email launches receive-only (@@OD:35@@, @@OD:99@@); a DATA circuit is always funded, built beside BDAT and part of the gate (@@OD:125@@; D-SMTP-20). An unauthenticated MX is refused with a DSN unless the user allows the domain (@@OD:38@@); each sending sidecar holds its own DKIM key under an opaque selector, at most 64 (@@OD:36@@).",
 "§14", "Q-SMTP-1 (with Q-SMTP-4, Q-SMTP-5)", "None."),
("X8", "How do server services push to clients in real time?",
 "(b) ControlId-sourced hints (§6.8), amending SUBPROTOCOL.md decision 6 so the control id may send subprotocol frames to clients, never receive them (C12), plus an HTTPS long-poll fallback in v0 (@@OD:17@@).",
 "§6", "Q-PROTO-1", "None."),
("X9", "Which connect changes may land on connect's `sidecar` branch?",
 "(b) §4.6's dispositions (@@OD:22@@), as @@OD:85@@ (C14 into M4) and @@OD:86@@ (C18) amend them.",
 "§4", "Q-REPO-2", "C17, after §18's size spike."),
("X10", "What client identity does a sidecar run under?",
 "Its own Required client (D-CORE-4, 5.8): a child of the device client in the same network where an sdk host or pairing provides one, else top-level; never the device's own client or one per agent (@@OD:4@@).",
 "§5 (with §20)", "Q-CORE-1 (with Q-CORE-2, Q-QUOTA-4)", "None."),
("X11", "What does \"all of these count towards transfer balance\" (PLAN.md:353) mean mechanically?",
 "(a) traffic bytes count: edges, shares, evs transfer and relayed same-network traffic; storage, sends, DNS entries and TLS endpoints are quotas (20.6; @@OD:10@@).",
 "§20 (with §6)", "Q-QUOTA-2 (with Q-QUOTA-5, Q-QUOTA-6, Q-PROTO-3)", "None."),
("X12", "MLS: does v0 ship it, build or fork, which ciphersuite, what group granularity, what do \"GKM\" and \"one session key stored in GKM\" mean, and what does gkm see?",
 "MLS in v0 (@@OD:1@@), built in house as 10.4's subset, its audit deferred (@@OD:43@@, @@OD:99@@), on ciphersuite 0x0010 (@@OD:44@@), one group per evs repo whose leaves are member devices while agents hold wraps (@@OD:60@@, @@OD:114@@). GKM is a delivery service plus wrapped, laddered generations in the file cluster (implied by @@OD:59@@), and gkm sees 10.6's rows: ciphertext, group id, epoch, sizes and sidecar ids, never a proposal, credential change, tree or key (@@OD:115@@).",
 "§10", "Q-KEYS-9 (with Q-KEYS-1, -2, -3, -4, -12)", "None."),
("X13", "What is the \"new file cluster\" (PLAN.md:61), and where does ordering live?",
 "(a) 19.6's two MinIO clusters at one site, an NVMe metadata cluster at EC:4 and an HDD segment cluster at EC:8, built from the final upstream source and ordered by the store's conditional writes, with no off-site copy in v0 (@@OD:18@@, @@OD:20@@, @@OD:21@@, @@OD:94@@; ordering @@OD:2@@); parity, 3.84 TB NVMe drives, push-log packing and a cold spare as recommended, the load inputs an engineering estimate (@@OD:116@@).",
 "§19 (with §11)", "Q-OPS-1", "None."),
("X14", "What runs the extension's sidecar?",
 "(a) a slimmed `sidecar.wasm` Worker, HTTPS-only first, and meanwhile (c) the native companion to a desktop `ur daemon`; never a hosted sidecar (18.8; @@OD:26@@).",
 "§18", "Q-SDK-1", "18.10's size spike, which decides C17 (@@OD:22@@)."),
("X15", "In what order are the products built after M2?",
 "(c) two tracks, with a second team on mail and burner (23.5; @@OD:9@@).",
 "§23", "Q-PHASE-1", "None."),
("X16", "Which tier numbers, and what shape of Team price?",
 "(b) PLAN's quotas and 20.4's Team price ($100 a month for 5 billable seats, then $20 a seat), overage only on transfer and storage, replies-only dropped (@@OD:27@@); overage at existing rates: transfer at the data-pack rate ($3 per TiB) and storage per GiB-month from §19.6's cost per usable TB, reviewed yearly (@@OD:122@@).",
 "§20", "Q-QUOTA-1", "None."),
("X17", "Which roots and keys does recURd use?",
 "ur.io/recurd on the main bringyour.com services, with no dedicated keys; recurd.dev redirects there (§12.4; @@OD:15@@, @@OD:108@@).",
 "§12 (with §2)", "Q-DNS-3", "None."),
("X18", "Which range carries overlay addresses?",
 "IPv4 only: a random /16 per network from 100.64.0.0/10 after C6a, which admins may cycle or replace (@@OD:28@@), a chosen block lying in 100.64/10 or RFC 1918 (Q-BRIDGE-7; @@OD:132@@).",
 "§17", "Q-BRIDGE-1", "None; Q-BRIDGE-7 bounds the choice."),
("X19", "How does evs stay git-compatible?",
 "A local git tier over authenticated http and ssh plus `git-remote-ur`; only the sidecar talks to evs (@@OD:24@@); @@OD:84@@ and @@OD:130@@ set the bind, with only TLS or ssh beyond loopback (11.11).",
 "§11", "Q-EVS-2", "None."),
("X20", "Which record primitives does this design provide, and where is the record designed?",
 "(b) 16.8's primitives and a frozen `record.proto` here; RECORD.md, an M0 deliverable reviewed before format 1 freezes, owns record semantics, search, exports, the verifiable log, disclosure, model receipts and cost (@@OD:25@@).",
 "§16", "Q-MCP-1", "None."),
]

OPEN_INTRO = (
"None. Every Q- item whose decider was the owner is decided: owner decisions 112-135 (2026-11-04) answered the last of "
"them, the residual confirmations included. Outside the Q- items, the owner keeps one launch call on measured data: "
"accepting the SNI loss that M7's census measures, before BS1 (D-MAIL-9; @@OD:34@@; §23.6)."
)
OPEN_OWNER = []

PEER_INTRO = (
"Open Q- items whose decider is peer review, as the sections state them, ordered by the milestone whose entry review "
"(Gn-in) needs the answer (§23.6). owner/DECISIONS.md leaves this engineering detail to the reviewers. Decided items "
"leave three more engineering residuals: Q-EVS-1's Q-EVS-6 (below); Q-QUOTA-3's benchmark and peer review of the escrow "
"order before M6 (§20.9, §23.6); and Q-SDK-1's size spike, which decides C17 (Q-REPO-2). The items the 2026-11-03 "
"design-review round closed ([Appendix B](#appendix-b-open-questions-register)) were not closed by human peer review, "
"and reviewers may reopen them (§3.11)."
)

# Q id | question | recommendation | blocks | needed by
PEER = [
("Q-TEST-1", "Copy connect's test helpers or export them?",
 "(a) `sidecartest` rebuilds them; (b) a `connect/connecttest` package if copies drift.", "T2", "M0"),
("Q-TEST-2", "The local stack lacks an object store, and its one Redis node accepts cross-slot commands production rejects: how does it match production?",
 "(a) a 3-master Redis Cluster and final-upstream MinIO locally and at the release gate, plus (b) a CROSSSLOT lint.", "T3", "M0"),
("Q-CORE-4", "Must a sidecar prove possession of its ClientKey?",
 "(b) on refresh and token exchange in v0, so a copied `by_client_jwt` alone mints no service token; (c) transport auth later.", "§7's token design", "M1"),
("Q-TEST-6", "Does §6.11's `oneof` ban cover every sidecar proto, or only envelope, stream and push messages?",
 "(b) those three, so `UrMlsCredential` keeps its oneof.", "§6.11's rules and 22.5's descriptor lint (M1)", "M1"),
("Q-CTX-4", "Who designs `ur share` (R-CTX-31): §9, the sharer's sidecar serving the file on a socket, or §11, an evs object sealed under a key in the link's fragment?",
 "(a) §9, as UI:36's `ur share` blocks.", "R-CTX-31", "M2"),
("Q-KEYS-11", "How long does GKM keep epoch objects?",
 "(a) 30 days, then until every leaf acking in the last 30 days has applied them.", "§19 sizing", "M2"),
("Q-EVS-6", "Must a head reader that does not replay verify per-file freshness?",
 "(a) no in v0, measuring how often phones read files older than the 64-version window.", "format 1, since (b) changes `EvsPush`", "M2"),
("Q-OPS-2", "Should small objects pack? Y2's HDD mix needs ~32,000 drive operations a second against ~8,000-12,800 (19.6), and gkm's `gen/` takes the metadata tier to ~5 sets by count, ~2 by bytes (19.9).",
 "(b), §11's 16 KiB inlining and debouncing, for segments in v0; (a) packing once drive operations pass half §22.8's rate; (a) for `gen/` before Y2.",
 "§11's locator format (M2); the Y2 pools (D-OPS-17)", "M2"),
("Q-BRIDGE-2", "How do bridge links reach targets: a multi client per target, or a link on the subject's own client?",
 "(c) a client per target now; own-client links where memory demands, the iOS tunnel first.", "link code, the iOS bridge", "M4"),
("Q-SDK-5", "Where does the iOS device role's code live, given that a root-package role links every root init and `protocol` descriptor into the extension?",
 "(a) the root if M4's measurement passes §4's 1 MiB gate, else (b) a leaf package `sidecar/device`.", "the iOS device role (M4's seam)", "M4"),
("Q-OPS-5", "Should `dns` deploy staged (`--only-older`, stopping at 25%) or in one pass like `dnsedge`?",
 "(a) staged.", "19.11's classes (M5)", "M5"),
]

INDEX_INTRO = (
"Every entry of the owner's record (owner/DECISIONS.md), by number: 1-111 from the interview of 2026-11-03; 112-125 "
"from the follow-up of 2026-11-04 and 126-135 from its second round. \"Settles\" names the X and Q- items the entry "
"decides. The decision is one line, faithful to the record; where owner/APPLY.md §2 or a later entry supersedes, "
"amends or confirms an entry, the line says so. \"Implemented in\" lists the sections whose text cites the entry as "
"\"owner decision N\"; a summary range such as `owner decisions 1-135` does not count as citing each entry."
)

# n | settles | decision (one line, with supersession). Rows 1-125 start from the third assembly's, with the notes that
# decisions 126-135 and owner/APPLY.md §2 add; rows 126-135 are new.
_UPD = {
27: (None, "PLAN's quotas; Team $100 a month for 5 billable seats, then $20 a seat; overage only on transfer and storage; replies-only dropped; @@OD:122@@ sets the overage rates."),
35: (None, "No outbound mail until the ZK preamble proofs are sound, fast and interop-tested; burner email launches receive-only. Its external audit is dropped by @@OD:99@@; @@OD:125@@ adds DATA coverage to the gate."),
94: (None, "v0 has one site, one metadata and one storage cluster, \"2 replicas\" read as 50% parity, and no off-site copy; it supersedes the off-site parts of @@OD:18@@ and @@OD:89@@; @@OD:116@@ confirms the parity reading."),
99: (None, "\"No review at the moment, just get it working\": no external security review for now; @@OD:35@@'s gate drops its audit and @@OD:43@@'s audit is deferred; @@OD:119@@ lets copy say \"end-to-end encrypted\" with this disclosed."),
7: (None, "evs grants a key as reader (repo keys) or reader+writer (signed heads accepted from the writer set); membership changes come only from keys allowed to grant, which @@OD:113@@ reads as binding the change, not the committer, and @@OD:128@@ extends to the signing leaf in the config group."),
8: (None, "Repo admins and network admins grant, verified through the config repo's delegation chain; in owner-bound repos @@OD:126@@ limits network admins to revoking and adding the visible audit member."),
24: (None, "A local git server (http and ssh) plus `git-remote-ur`; only the sidecar talks to evs. Its \"loopback only\" is superseded by @@OD:84@@; @@OD:130@@ makes the listener TLS-only beyond loopback."),
28: (None, "An IPv4 overlay: a random /16 per network, by default from 100.64.0.0/10, which admins may cycle or choose. Its \"private names (v1)\" is superseded by @@OD:85@@; @@OD:132@@ narrows a chosen block to 100.64/10 or RFC 1918."),
62: (None, "A recovery code plus admin re-add; @@OD:126@@ keeps an admin re-add out of owner-bound repos, and @@OD:127@@ counts the recovery key as one of k for authority statements."),
82: (None, "Repo deletion is a soft delete; keys are shredded after 7 days unless restored, or at once with `--now`; under @@OD:133@@ no preservation hold defers it."),
84: (None, "Forwards and local service listeners bind 0.0.0.0/:: by default; `--listen` narrows. Supersedes @@OD:24@@'s loopback rule and D-TRUST-8's loopback default; @@OD:130@@ confirms TLS only beyond loopback for git over http, IMAP and SMTP submission."),
89: (None, "v0 runs at one site: RPO 5 min for metadata and 1 h for segments, RTO 4 h, for drive and host failures only (@@OD:94@@), which also supersedes its off-site replication; a second site is decided from operating data."),
90: (None, "No backups of key slots or wraps, so erasure is immediate; devices re-seed content after a site loss. Its off-site replication of other data is superseded by @@OD:94@@ (no off-site copy)."),
95: (None, "Automated abuse actions act at once, with human review within 24 h; business-hours staff in v0, 24/7 on-call by v1; @@OD:134@@ adds an emergency pager from M5."),
98: (None, "Disclose inbound interception risk and label each message validated or opportunistic; sidecars watch DNS and CT; a Team strict mode; @@OD:135@@ defines \"validated\"."),
103: (None, "Sidecar-held child and admin-refused tokens get a hard 7-day expiry, shipped with the P0 auth fix; @@OD:131@@ confirms that the sdk's window clients keep today's lifetime."),
110: (None, "One admin signature admits a sidecar or member; admin-set and authority-key changes need k-of-n admin signatures. Read with @@OD:112@@ (a member's own device admits the member's new device alone) and @@OD:127@@ (a recovery key counts as one of k)."),
113: (None, "The phrase \"only from keys allowed to grant\" in @@OD:7@@ binds the change, not the committer: any writer leaf commits an Add or Remove that a signed grant, admission or revocation requires, members reject one without it, and D-KEYS-7 is withdrawn; @@OD:128@@ extends it to the signing leaf in the config group."),
}
INDEX = []
for (_n, _settles, _dec) in _P3['INDEX']:
    if _n in _UPD:
        _s, _d = _UPD[_n]
        INDEX.append((_n, _s or _settles, _d))
    else:
        INDEX.append((_n, _settles, _dec))
INDEX += [
(126, "Q-ACL-10 (X3)", "Admin authority under @@OD:8@@ does not reach a member's owner-bound repos without the member's consent: admins revoke there and add only @@OD:63@@'s audit member; any other reader needs the member's signed consent (the member's own device or recovery key, a first device from an invite, or an `OwnerConfirm` countersignature); members' devices refuse other Adds, park such devices and alarm on admissions under them they did not sign."),
(127, "Q-TEAM-11", "A recovery key counts as one signature toward k for authority statements (AdminSet and authority-key changes), after a 72 h window in which any admin device may veto; personal networks (k = 1) recover alone, and @@OD:110@@ holds."),
(128, "Q-KEYS-14", "In the config repo's MLS group, the leaf that signed an admission or revocation commits the MLS change it requires, even if not a config writer; recovery-admitted devices self-join by external commit; writing config records stays admin-only. Extends @@OD:113@@."),
(129, "Q-TRUST-9 (Q-MCP-4's residual)", "Any admitted reader sidecar, agents included, may witness HeadCheck; shared-group writers alarm at 24 h and stop at `ServiceSettings.witness_bound_hours` (default 72 h, 24-168 h), which §2.8 publishes as the exposure bound for a withheld Remove; rotations, Removes and revocations never stop."),
(130, "Q-BRIDGE-5 residual (X19)", "Beyond loopback, git over http, IMAP and SMTP submission serve TLS only (git may use ssh), plaintext stays on 127.0.0.1 and ::1, and port forwards are unaffected; it confirms the rule @@OD:84@@ left open."),
(131, "Q-PHASE-7 residual", "The 7-day hard expiry applies only to sidecar-held child and admin-refused tokens; the sdk's window clients keep today's lifetime until fleet-wide expiry follows app adoption, so the P0 needs no app release. Confirms @@OD:103@@'s scope."),
(132, "Q-BRIDGE-7 (X18)", "A chosen overlay /16 must lie in 100.64.0.0/10 or RFC 1918, narrowing @@OD:28@@'s \"any /16\"; `ur bridge block` refuses other ranges, and once C6a lands public exits refuse both."),
(133, "Q-EVS-7", "Preservation holds never block user-initiated shredding (`--now`, the 7-day timer of @@OD:82@@, per-entry erasure); they pause only the server's TTL sweeps and GC, conditional on counsel confirming."),
(134, "Q-ABUSE-6", "Business-hours review with automated actions holding until reviewed (@@OD:95@@), plus an on-call pager from M5 only for registrar, registry and law-enforcement emergency notices, EU removal orders included; 24/7 on-call in v1."),
(135, "Q-MAIL-13 (Q-ABUSE-1's residual)", "\"Validated\" means REQUIRETLS, or TLSA in our signed zone for the SNI host plus a sender on a versioned list of DANE- or MTA-STS-enforcing operators, identified by forward-confirmed PTR or aligned DKIM `d=`; otherwise \"opportunistic\". Defines @@OD:98@@'s label."),
]
DATES = {n: ('2026-11-03' if n <= 111 else '2026-11-04') for n in range(1, 136)}

# Known gaps: section text that still contradicts an owner decision (where, text, decision, note). Filled from
# validation; empty when none is found.
KNOWN_GAPS_INTRO = ("The assembly's checks found section text that still contradicts an owner decision. Each row names "
                    "the place, the text and the decision that governs; each needs a section edit.")
KNOWN_GAPS = []
