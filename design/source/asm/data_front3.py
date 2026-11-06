# Front matter and the "Owner decisions" section for DESIGN.md, third assembly (2026-11-04), written from the section
# files as last edited (2026-11-04 05:43), CONVENTIONS.md §0, §1 and §7, owner/APPLY.md (§2, §3, §5, §6) and
# owner/DECISIONS.md (125 entries: 1-111 of 2026-11-03, 112-125 of 2026-11-04). Loaded with runpy.
# "@@OD:N@@" marks a link to row N of the decisions-by-number table; assemble3.py resolves it.
# "@@NAME@@" placeholders are counts that assemble3.py computes from the section text.

TITLE = "# Sidecar infrastructure: technical design"

STATUS = ("Status: draft for peer review, 2026-11-03. Nothing described here is implemented. "
          "The owner's design decisions of 2026-11-03 are applied throughout.")

SCOPE = (
"This document designs the sidecar infrastructure: the shared substrate under recURd, the private record of "
"agent work, and under burner email, the consumer product in the URnetwork apps. It covers the new "
"`github.com/urnetwork/sidecar` repo (the `sidecar.Sidecar` core, the sidecar subprotocol, the stdio MCP server, "
"the `ur` CLI and the service engines); the horizontally scaled services that the server repo hosts for it (evs, "
"gkm, sockets, dns with its dns edges, certs, tlsedge, smtpedge and mxedge), with the team-management and "
"access-control additions; `sdk/sidecar.go`; the changes these need on connect's `sidecar` branch; and their "
"build and deployment through sn, warp, config, vault, build, xops and mmm. It starts from the owner's PLAN.md "
"(sidecar/design/PLAN.md). Out of scope: the apps, console and extension UI (only their seams are designed), harnesses "
"and model hosting, the feedback service, recURd's record semantics beyond the X20 primitives (RECORD.md, an M0 "
"deliverable designed separately), and prices beyond §20's tier and quota mechanics."
)

DIRECTIVE = """## Owner directive

The owner's words, 2026-11-03 (CONVENTIONS.md §0; the directive overrides PLAN.md where they conflict):

> **"End to end encryption is a must. The storage, tls edge, mail must only see encrypted bytes and some small header values like sni and spam headers."**

It is a requirement, not an open question, and it binds every section. In short:

- **TLS edge (X1).** TLS terminates in the listening sidecar. `tlsedge` routes by SNI (passthrough), never holds a user's TLS key and has no termination mode; PLAN.md:84's edge termination is superseded.
- **Storage (X2).** evs and gkm see only encrypted bytes plus small header values. Paths, file names, commit messages, author fields beyond the authenticated client id, and contents are encrypted; PLAN.md:59's plaintext paths are superseded. The published metadata list (§2.8, Appendix G) enumerates every header value.
- **Outbound mail (X7).** TLS runs end to end from the sidecar's mail server to the destination MX through `smtpedge`, which sees only ciphertext plus a small declared preamble. Edge-terminated submission and an SES relay are ruled out.
- **Inbound mail (X6).** TLS terminates on a device or a customer-run sidecar, never at a URnetwork edge. The edge may see SNI, the connecting IP, the EHLO name and spam-relevant values; encrypt-on-receipt at the edge is ruled out.
- **Everything else.** Connect traffic between sidecars requires e2e encryption (Required, never Opportunistic or Off). gkm sees only encrypted MLS handshake data plus small headers. DNS data is public but reveals as little as possible (opaque labels, wildcards). A server component that would see plaintext content is a design error and is never offered as an option.

The sections cite the directive as "the directive", "owner directive 2026-11-03", "CONVENTIONS §0" or "§0"."""

RULES = """## Owner rules

Hard constraints (CONVENTIONS.md §1); the sections do not re-litigate them.

1. **Code placement.** New pieces, the MLS implementation included, live in the sidecar repo. The server repo adds the horizontally scaled services that support them, integrates them, and takes the network and team client management and access-control enhancements. The sdk exposes the sidecar components.
2. **Dependency direction.** `sidecar` depends on `connect`, never on `server` or `sdk`; `server` and `sdk` import `sidecar`.
3. **Deleted code.** The message repo and connect/MESSAGEREVIEW.md are being deleted; nothing uses, cites or reuses them.
4. **Branches.** All sidecar work happens on a branch named `sidecar` in every repo it touches.
5. **Layout.** PLAN.md's tree: `go.mod`, `sidecar.go`, `protocol/`, `mcp/`, `cli/main.go`; server-only engines go in child packages (@@OD:104@@, §4.4).
6. **Scope.** The apps are out of scope; they use the sidecar directly, and the extension runs it as a web worker. This design covers their seams, not their UI.
7. **Product facts.** recURd is not tokenized and uses the URnetwork network for worldwide reach.
8. **PLAN.md is the default.** PLAN.md statements are requirements; a technical problem with one keeps the PLAN position visible and goes to the owner as a Q- item."""

BRANCH = """## Branch policy

All sidecar work happens on a branch named `sidecar` in every repo it touches (owner rule 4). In short (§23.9, §4.8, D-REPO-5; @@OD:117@@ and @@OD:118@@):

- A repo's `sidecar` branch is cut from `main` when a milestone first touches it (§23.4): sidecar, connect, server, sdk and build in M0; mmm in M1; config, vault and xops in M2; sn in M4; warp in M5. The extension and app repos get one only if the owner opts in.
- `main` merges into every `sidecar` branch weekly and before each gate, in the order connect, sidecar, sdk, sn, server, warp/config/vault/xops/mmm, build, re-pinning the source-graph lock each time. Nothing is rebased.
- At each milestone's exit review (Gn-out), every touched repo, server and sdk included, merges `sidecar` into `main` in that order, connect's default-off changes first, and re-pins the lock. Deploys, pilots and releases build from `main`, with features dark behind `config/<env>/sidecar.yml`. Each §19.7 migration group's SQL merges at the Gn-out whose deploy first applies it, so M3's pilot runs on production.
- The sidecar repo is public from 2026-11-04, unscrubbed, with its documents and history. server's and sdk's `sidecar` branches use their normal public remotes, and no merge waits for RS1 (D-PHASE-5 is withdrawn). §4.8, §4.11, D-REPO-8 and D-REPO-9 still describe the superseded scrub, private mirrors and RS1 merges ([Known gaps](#known-gaps))."""

HOW = """## How to review

- **Where the decisions and questions are.** Every section follows one template: purpose and scope, requirements, what exists today, design, alternatives considered, decisions proposed, open questions, departures from PLAN.md, interfaces, risks and phasing. The [owner decisions](#owner-decisions) section below gives X1-X20, the [open owner questions](#open-owner-questions), the items [left to peer review](#left-to-peer-review), the [owner decisions by number](#owner-decisions-by-number) and the [known gaps](#known-gaps) between the section text and those decisions. [Appendix A](#appendix-a-decision-register) lists all @@ND@@ D- items (@@NDW@@ withdrawn). [Appendix B](#appendix-b-open-questions-register) lists all @@NQ@@ Q- items: @@NQDEC@@ decided by the owner, @@NQOPEN@@ open (@@NQOWN@@ for the owner, @@NQPEER@@ for peer review), @@NQCLOSED@@ closed by peer review and @@NQW@@ withdrawn. @@NRESOPEN@@ decided items leave a residual the owner must confirm, and @@NRESSTALE@@ more still state residuals that owner decisions of 2026-11-04 answered.
- **Id families.**
  - `X1`-`X20`: cross-cutting decisions. Each has one owning section, which resolves it in a Q- item whose text starts with the X id.
  - `R-CODE-n`: a requirement in section CODE's requirements table, with its source (a PLAN.md line, a product source, an owner decision, or "derived").
  - `D-CODE-n`: a proposed decision with its rationale (*Why:*), or a withdrawn one that names what superseded it.
  - `Q-CODE-n`: a question with options, a recommendation, what it blocks and its decider (owner or peer review). It is open, decided by the owner, closed by peer review, or withdrawn; a decided item records the decision and any residual.
  - `I-1`..`I-18`: the security invariants of §2.9, binding on every section.
  - CODEs: CTX §1, TRUST §2, ARCH §3, REPO §4, CORE §5, PROTO §6, TEAM §7, ACL §8, SOCK §9, KEYS §10, EVS §11, DNS §12, TLS §13, SMTP §14, MAIL §15, MCP §16, BRIDGE §17, SDK §18, OPS §19, QUOTA §20, ABUSE §21, TEST §22, PHASE §23.
  - Other families: C1-C18 (connect changes, §4.6, Appendix E), F1-F10 (flows, §3.7), KF1-KF7 (MLS flows, §10.7), S1-S10 (test scenarios, §22.7), M0-M9 (milestones, §23.4), G0, Gn-in and Gn-out (review gates, §23.8), RS1-RS3 (recURd stages) and BS1 (the burner launch), W1-W11 (warp changes, §19.5), Y1-Y2 (load years, §19.6), MG0-MG9 (migration groups, §19.7), T1-T6 (test tiers, §22.4), TL1-TL4 (MX authentication levels, §14.4), E1-E3 and Z1-Z6 (preamble proof checks, §14.5), EX1-EX8 (operator capabilities, §2.8), P0 (the staged auth fix, §7.4), TB1-TB3 (trust boundaries, §2.4), H1 and H3 (connect carriers), and the metadata rows of §2.8 and Appendix G (connect-1, api-7, evs-11, ...). An id after a `[R:key]` link, such as "§5 R8" or "S11", names an item inside that research sheet. No external review gates any milestone (@@OD:99@@).
- **Notation** (owner/APPLY.md §3; D-ARCH-1).
  - `<root>` is the user-content root, ur.network (@@OD:13@@). `<net>` is the network's opaque, immutable label (@@OD:14@@), or the opt-in alias where the user chose one. `<blabel>` is a burner's generated word-number label, so a burner address is `<name>@<blabel>.<net>.<root>` (@@OD:32@@).
  - Burners use a wildcard MX `*.<net>.<root> MX 10 mx.<net>.<root>`, a DANE TLSA record at `_25._tcp.mx.<net>.<root>` and SNI `mx.<net>.<root>`. A wildcard owner name carries no CNAME (RFC 1034 §3.6.2, RFC 2181 §10.1); wildcard A and AAAA records (the shared lb addresses) sit beside the wildcard MX.
  - Platform and service names live on bringyour.com (@@OD:16@@). ur.io is the web; recURd runs at ur.io/recurd, and recurd.dev redirects there (@@OD:15@@).
  - The bridge overlay is a random IPv4 /16 per network, drawn from 100.64.0.0/10 by default (@@OD:28@@).
  - `<host>` is a zone-relative host. `<edge>`, `<md>`, `<label>` and `<broot>` are retired, and `<me>` appears only inside PLAN.md quotations.
- **Owner decisions.** "Owner decision N" cites entry N of the owner's record, owner/DECISIONS.md: entries 1-111 come from the interview of 2026-11-03 and entries 112-125 from the follow-up of 2026-11-04, which answered the owner questions the first fix rounds raised. Every such citation links to row N of [owner decisions by number](#owner-decisions-by-number), which states the decision in one line, notes supersession (owner/APPLY.md §2 and the later entries) and lists the sections that cite it. "Decided by owner 2026-11-03 (owner decision N)" or "Decided by owner 2026-11-04 (owner decision N)" marks a Q- item the owner settled; "implied by owner decision N" marks one that follows from it. Where section text still predates a 2026-11-04 entry, [Known gaps](#known-gaps) names the place; the decision governs.
- **PLAN.md is the default.** PLAN.md statements are requirements unless a D- or Q- item says otherwise. Each section's "Departures from PLAN.md" lists its exceptions, and [Appendix F](#appendix-f-planmd-traceability) traces every PLAN.md line.
- **Source keys.** P5 = sidecar/design/pitch5.html, PM = sidecar/design/product.md, MK2 = sidecar/design/market2.md, FB = sidecar/FEEDBACK-SYSTEM.md, MM = sidecar/design/mocks/urnetwork-mobile.html, RA = sidecar/design/mocks/recurd-app.html, TM = sidecar/design/mocks/team-management.html, REC = sidecar/design/reports/Agent work record gaps and features.md, UI = cli/UI.md, EXT = connect/EXTENDERUPDATE.md, PLAN = sidecar/design/PLAN.md.
- **Citations.** Code is cited as `repo/path/file.go:LINE`, relative to the urnetwork checkout. `[R:key]` links a research fact sheet in [design-research/](design-research/) ([Appendix H](#appendix-h-research-sources)). "CONVENTIONS §0" is the owner directive above, "CONVENTIONS §1" the owner rules, and "CONVENTIONS §7" the X registry that the X1-X20 table replaces."""

DECISIONS_INTRO = (
"The owner answered 111 questions on 2026-11-03, after the end-to-end-encryption directive, and 14 more on 2026-11-04 "
"(entries 112-125), which settled the owner questions the fix rounds had raised by then. The sections were edited to "
"those answers; where two answers disagree, owner/APPLY.md §2's supersession table and the later entries govern, and the "
"table of [owner decisions by number](#owner-decisions-by-number) notes each case. Text in §1, §2.8, §3, §4, §5, §14, "
"§17, §20 and §21 still states some questions the 2026-11-04 entries answered; [Known gaps](#known-gaps) lists each "
"place. This section lists the cross-cutting decisions, what is still open for the owner, what is left to peer review, "
"every decision with the sections that implement it, and those gaps."
)

X_INTRO = (
"X1-X20 are the cross-cutting decisions the research surfaced (CONVENTIONS §7). Each row is built from its owning "
"section's `[Xn]` Q- item: its question, the decision with the owner decisions that settle it, and its residual "
"as the item states it, with a note where a 2026-11-04 entry has since answered that residual. Every X item is decided."
)

# X | question | decision | owning § | Q id | residual
X_ROWS = [
("X1", "Where does TLS end, and how does TCP 443 split? Who orders certificates for device-held keys, how do a team's devices share the wildcard, and is abuse handling without inspection enough?",
 "TLS ends in the listening sidecar (the directive), reached through an `ssl_preread` SNI split on the shared lb addresses (@@OD:34@@). certs' CSR proxy in URnetwork zones and a customer CAA-pinned account on Team custom domains (@@OD:39@@); per-device keys plus scope sublabels, never a shared key (@@OD:40@@); abuse hooks plus a verified account before any Community publish (@@OD:41@@).",
 "§13", "Q-TLS-1 (with Q-TLS-2, Q-TLS-3, Q-TLS-4)", "None."),
("X2", "Which header values may evs see, and how do head reads and subpath subscriptions work without plaintext paths?",
 "Keyed path tokens in an object index, token-prefix subscriptions, path-key rotation on member removal, and all storage state as objects in the file cluster (@@OD:2@@).",
 "§11", "Q-EVS-1", "Q-EVS-6 (peer review): must a head reader that does not replay verify per-file freshness?"),
("X3", "Who is the policy authority?",
 "A customer key authority from v0, compiled on customers' devices, in the encrypted config repo; servers enforce a signed id-only projection (owner decisions 3, 5-8 and 110).",
 "§8 (with §7)", "Q-ACL-1", "Q-ACL-10 (owner): does @@OD:8@@'s admin grant reach owner-bound kinds?"),
("X4", "Which registrable domain carries user names?",
 "(b1) ur.network for user content only: signed, strict DMARC, PSL-listed when eligible (@@OD:13@@); platform names move to bringyour.com (@@OD:16@@).",
 "§12", "Q-DNS-1", "None."),
("X5", "What is a network's label?",
 "(a) opaque, random and immutable, with an opt-in alias equal to network_name (@@OD:14@@).",
 "§12", "Q-DNS-2", "None."),
("X6", "How does mxedge route inbound mail without terminating TLS? Which devices receive, what is the burner format, and are senders without STARTTLS refused?",
 "Inbound TLS ends on customer receivers (the directive). mxedge routes by SNI alone with DANE TLSA, and senders without SNI defer (@@OD:31@@, @@OD:34@@). Always-on receivers plus the iOS app in the foreground (@@OD:12@@); burners `<name>@<blabel>.<net>.<root>` under a wildcard MX (@@OD:32@@); plaintext senders refused with 530, plus a Team direct MX (@@OD:33@@).",
 "§15", "Q-MAIL-1 (with Q-MAIL-2, Q-MAIL-3, Q-MAIL-9)", "None in the items; BS1 waits for the owner to accept the loss D-MAIL-9's M7 census measures."),
("X7", "How is the preamble made trustworthy, and what ships before a sound proof? What happens to an unauthenticated MX, and who holds DKIM keys?",
 "Nothing ships until 14.5's proofs pass D-SMTP-16's gate, with no external audit; burner email launches receive-only (@@OD:35@@, @@OD:99@@). An unauthenticated MX is refused with a DSN unless the user allows the domain (@@OD:38@@); each sending sidecar holds its own DKIM key (@@OD:36@@).",
 "§14", "Q-SMTP-1 (with Q-SMTP-4, Q-SMTP-5)", "§14.12 still asks the owner to accept BDAT-only coverage or fund a DATA circuit; @@OD:125@@ (2026-11-04) funds it and puts DATA coverage in D-SMTP-16's gate ([Known gaps](#known-gaps))."),
("X8", "How do server services push to clients in real time?",
 "(b) ControlId-sourced hints, amending SUBPROTOCOL.md decision 6 so the control id may send subprotocol frames to clients (C12), with an HTTPS long-poll fallback in v0 (@@OD:17@@).",
 "§6", "Q-PROTO-1", "None."),
("X9", "Which connect changes may land on connect's `sidecar` branch?",
 "(b) §4.6's dispositions (@@OD:22@@), as @@OD:85@@ (C14 into M4) and @@OD:86@@ (C18) amend them.",
 "§4", "Q-REPO-2", "C17, after §18's size spike."),
("X10", "What client identity does a sidecar run under?",
 "Its own Required client: a child of the device client in the same network where an sdk host or pairing provides one, else top-level; never the device's own client or one per agent (@@OD:4@@).",
 "§5 (with §20)", "Q-CORE-1 (with Q-CORE-2, Q-QUOTA-4)", "None."),
("X11", "What does \"all of these count towards transfer balance\" (PLAN.md:353) mean mechanically?",
 "(a) traffic bytes count: edges, shares, evs transfer and relayed same-network traffic; storage, sends, DNS entries and TLS endpoints are quotas (@@OD:10@@).",
 "§20 (with §6)", "Q-QUOTA-2 (with Q-QUOTA-5, Q-QUOTA-6, Q-PROTO-3)", "None."),
("X12", "MLS: does v0 ship it, build or fork, which ciphersuite, what group granularity, what do \"GKM\" and \"one session key stored in GKM\" mean, and what does gkm see?",
 "MLS in v0 (@@OD:1@@), built in house as 10.4's subset (@@OD:43@@; its audit deferred by @@OD:99@@), on ciphersuite 0x0010 (@@OD:44@@), one group per evs repo (@@OD:60@@), whose leaves are member devices while agents hold wraps (@@OD:114@@). GKM is a delivery service plus wrapped, laddered key generations in the file cluster (implied by @@OD:59@@), and gkm sees ciphertext plus group id, epoch, sizes and 10.6's sidecar-id rows (@@OD:115@@).",
 "§10", "Q-KEYS-9 (with Q-KEYS-1, -2, -3, -4, -12)", "None."),
("X13", "What is the \"new file cluster\" (PLAN.md:61), and where does ordering live?",
 "(a) 19.6's two MinIO clusters at one site, a metadata (NVMe, EC:4) and a segment (HDD, EC:8) cluster built from the final upstream source, ordered by the store's conditional writes, with no off-site copy in v0 (@@OD:18@@, @@OD:20@@, @@OD:21@@, @@OD:94@@; ordering @@OD:2@@); parity, 3.84 TB NVMe drives, push-log packing and a cold spare as recommended (@@OD:116@@).",
 "§19 (with §11)", "Q-OPS-1", "None."),
("X14", "What runs the extension's sidecar?",
 "(a) a slimmed `sidecar.wasm` Worker, HTTPS-only first, with (c) the native companion to a desktop `ur daemon` meanwhile; never a hosted sidecar (@@OD:26@@).",
 "§18", "Q-SDK-1", "The size spike (18.10), which decides C17."),
("X15", "In what order are the products built after M2?",
 "(c) two parallel tracks, with a second team for mail and burner (@@OD:9@@).",
 "§23", "Q-PHASE-1", "None."),
("X16", "Which tier numbers, and what shape of Team price?",
 "(b) PLAN's quotas; Team at $100 a month for 5 billable seats, then $20 a seat; overage only on transfer and storage; replies-only dropped (@@OD:27@@).",
 "§20", "Q-QUOTA-1", "§20.12 still asks the owner for Team's overage prices; @@OD:122@@ (2026-11-04) sets existing rates, as §20.12 recommends ([Known gaps](#known-gaps))."),
("X17", "Which roots and keys does recURd use?",
 "ur.io/recurd on the main bringyour.com services, with no dedicated infrastructure or keys; recurd.dev redirects there (@@OD:15@@, @@OD:108@@).",
 "§12 (with §2)", "Q-DNS-3", "None."),
("X18", "Which range carries overlay addresses?",
 "IPv4 only: a random /16 per network from 100.64.0.0/10 after C6a, which admins may cycle or replace with any /16 (@@OD:28@@).",
 "§17", "Q-BRIDGE-1", "Q-BRIDGE-7 (owner): may a chosen block lie outside 100.64/10 and RFC 1918?"),
("X19", "How does evs stay git-compatible?",
 "A local git tier over authenticated http and ssh plus `git-remote-ur`; only the sidecar talks to evs (@@OD:24@@), and @@OD:84@@ sets the bind.",
 "§11", "Q-EVS-2", "Q-BRIDGE-5's residual (owner): TLS-only content listeners off loopback."),
("X20", "Which record primitives does this design provide, and where is the record designed?",
 "(b) 16.8's primitives and a frozen `record.proto` here; RECORD.md, an M0 deliverable reviewed before format 1 freezes, owns the record's semantics (@@OD:25@@).",
 "§16", "Q-MCP-1", "None."),
]

OPEN_INTRO = (
"Open Q- items whose decider is the owner, then the residual confirmations that decided items leave, each as its "
"section states it. \"Needed by\" is the milestone whose entry review (Gn-in) §23.6 makes wait for the answer. "
"Owner decisions 112-125 (2026-11-04) answered every question owner/APPLY.md §5 listed. The open items are the rest: "
"Q-TEAM-11, Q-EVS-7, Q-MAIL-13, Q-BRIDGE-7 and Q-ABUSE-6, which the fix rounds raised and APPLY.md §5 did not list; "
"Q-TRUST-9, Q-ACL-10 and Q-KEYS-14, raised since the 2026-11-04 answers; and Q-SMTP-6, which §14 still presents as "
"open although @@OD:124@@ decided it. Not a Q- item: burner launch (BS1, M8) also waits for the owner to accept the "
"loss D-MAIL-9's M7 census measures."
)

# Q id | question | recommendation | blocks | needed by
OPEN_OWNER = [
("Q-TRUST-9", "Who is D-TRUST-10's witness, and when do shared-group writers stop without one? As drafted, writers in groups with another member's devices stop after 24 h without a member device's check, halting lone cloud agents (@@OD:49@@), weekend CI and travelling admins, while wakes arrive only at M8.",
 "(c): any admitted reader sidecar, agents included, witnesses; alarm at 24 h, stop at 72 h; plus a per-network `ServiceSettings.witness_bound_hours` (24-168 h) that §2.8 states as the exposure bound.",
 "D-TRUST-10 and §6.6's settings (M2)", "M2"),
("Q-TEAM-11", "May a recovery key sign an authority statement, such as an AdminSet change, given @@OD:3@@'s recovery and @@OD:110@@'s k of n?",
 "(b) as one signature toward k, with the 72 h window any admin device may veto, keeping k of n whenever k > 1 while personal networks (k = 1) recover.", "7.9's record format (M2)", "M2"),
("Q-ACL-10", "Does @@OD:8@@'s \"network admins can always grant or revoke\" reach owner-bound kinds, the vaults and mailboxes?",
 "(a) no: admins revoke there and add only @@OD:63@@'s visible audit reader; other readers need the owner's consent (§8.5, D-ACL-13).", "§8.5's kind defaults, config.proto (M2)", "M2"),
("Q-KEYS-14", "Only admin roles write the config repo (§8.8), so under @@OD:113@@ a self-admitted device (@@OD:112@@) reads no config until an admin's device adds it, though @@OD:113@@ says no membership change waits for an admin: who commits there?",
 "(a) the leaf that signed an admission or revocation commits it, and recovery-admitted devices self-join.", "gkm.proto (M2)", "M2"),
("Q-EVS-7", "Does a preservation hold pause user-initiated shredding (`--now`, the 7-day timer, slot erasure)?",
 "(b) yes, for in-scope records only, after counsel, with `--now` answered as deferred and the practice disclosed.", "§21.9's holds and §22.5's §21 row (M5)", "M5"),
("Q-SMTP-6", "Which IPv4 addresses send outbound mail, under which PTR names, given @@OD:34@@'s shared lb addresses and FCrDNS? *Decided 2026-11-04 by @@OD:124@@: (a), the shared lb addresses with PTR names under bringyour.com; §14.12 still shows it open ([Known gaps](#known-gaps)).*",
 "As §14.12 states it: (b) about 8 mail-only addresses, if \"currently\" allows; under (a), PTRs under `<root>`.", "M9's entry review; the HE request; §19.5", "M9's entry, per its Blocks; §23.6 omits it as decided"),
("Q-MAIL-13", "What makes a received message \"validated\" (@@OD:98@@), when a receiver sees only REQUIRETLS, which few originators set?",
 "(b) also when the SNI host has TLSA in a signed zone and the sender is a listed DANE- or MTA-STS-enforcing operator.", "§15.7's `tls_label` (M7)", "M7"),
("Q-BRIDGE-7", "May a chosen overlay block lie outside 100.64/10 and RFC 1918, as @@OD:28@@'s \"any /16\" allows?",
 "(b) only 100.64/10 or RFC 1918, which public exits refuse once C6a lands.", "`ur bridge block` validation (M4)", "M4"),
("Q-ABUSE-6", "With @@OD:95@@'s business-hours v0 staff, how do v0's review clocks, registrar notices and legal deadlines run overnight and at weekends?",
 "(b) business hours, machine actions holding until reviewed, plus a weekend pager for registrar, registry and law-enforcement emergencies.", "M5's public names", "M5"),
]

RESIDUAL_INTRO = (
"Owner confirmations that decided items leave, as the sections state them: Q-PHASE-7's and Q-BRIDGE-5's, which the "
"sections and owner/APPLY.md §2 added, then the six owner/APPLY.md §5 listed. Owner decisions 115, 116 and 121 settled "
"three of the six, and their sections say so; owner decisions 117, 122 and 125 settled the other three, whose sections "
"still state them as open ([Known gaps](#known-gaps))."
)

RESIDUAL_OWNER = [
("Q-PHASE-7", "Confirm that sdk window clients, never sidecar-held, stay outside D-TEAM-14's 7-day expiry (§7.4).",
 "Confirm as §7.4 drafts it.", "D-TEAM-14's scope, shipped with the P0", "M0"),
("Q-BRIDGE-5", "Off loopback, do git over http, IMAP and SMTP submission serve TLS only (git may also use ssh), with plaintext only on loopback?",
 "(a) adopt, since otherwise Basic auth, SMTP AUTH and IMAP LOGIN cross the LAN in clear.", "§11.11's listeners (v0b) and §15.10's (M7)", "M2"),
("Q-REPO-4", "§4.14 still asks the owner to confirm D-REPO-8's M0 timing and scrub list (§4.11) before the first pin.",
 "Answered by @@OD:117@@ (2026-11-04): no scrub, and D-REPO-8 is withdrawn; @@OD:118@@ makes the repo public now. §4 is not yet updated.", "—", "answered"),
("Q-SMTP-1", "§14.12 still asks, for M9's entry review: accept the census-measured BDAT-only coverage loss, or fund a DATA circuit (D-SMTP-17)?",
 "Answered by @@OD:125@@ (2026-11-04): always fund a DATA circuit, and DATA coverage joins D-SMTP-16's gate. §14 is not yet updated.", "—", "answered"),
("Q-QUOTA-1", "§20.12 still asks: what are Team's overage prices?",
 "Answered by @@OD:122@@ (2026-11-04): (a), transfer at the data-pack rate ($3/TiB) and storage per GiB-month from the cluster's cost per usable TB. §20 is not yet updated.", "—", "answered"),
("Q-OPS-1", "Before the hardware order: \"2 replicas\" as erasure-coding parity, the NVMe drive size, the Y1 and Y2 inputs, packing week-old push logs onto HDD, a cold spare.",
 "Settled by @@OD:116@@ (2026-11-04) as recommended; §19.14 records no residual.", "—", "settled"),
("Q-KEYS-12", "Confirm gkm's visible values: ciphertext plus group id, epoch and sizes, and 10.6's rows, which show membership as sidecar ids.",
 "Confirmed by @@OD:115@@ (2026-11-04); §10.12 records no residual. §2.8's gkm-4 and gkm-7 still lag ([Known gaps](#known-gaps)).", "—", "settled"),
("Q-TLS-8", "Which ports may published names use besides 443?",
 "Settled by @@OD:121@@ (2026-11-04): 8443, 8883 and 5671; §13.13 records no residual.", "—", "settled"),
]

PEER_INTRO = (
"Open Q- items whose decider is peer review, as the sections state them; owner/DECISIONS.md leaves this "
"engineering detail to the reviewers. Two decided items also leave peer-review residuals: Q-QUOTA-3 (the escrow-order "
"benchmark and review, before M6) and Q-SDK-1 (the size spike that decides C17, as Q-REPO-2 notes)."
)

PEER = [
("Q-CTX-4", "Who designs `ur share` (R-CTX-31): §9, the sharer's sidecar serving the file on a socket, or §11, an evs object sealed under a key in the link's fragment?",
 "(a) §9, as UI:36's `ur share` blocks.", "R-CTX-31", "M2"),
("Q-CORE-4", "Must a sidecar prove possession of its ClientKey?",
 "(b) on refresh and token exchange in v0, so a copied `by_client_jwt` alone mints no service token; (c) transport auth later.", "§7's token design", "M1"),
("Q-TEST-6", "Does §6.11's `oneof` ban cover every sidecar proto, or only envelope, stream and push messages?",
 "(b) those three, so `UrMlsCredential` keeps its oneof.", "§6.11's rules and 22.5's descriptor lint (M1)", "M1"),
("Q-TEST-1", "Copy connect's test helpers or export them?",
 "(a) `sidecartest` rebuilds them; (b) a `connect/connecttest` package if copies drift.", "T2", "M0"),
("Q-TEST-2", "The local stack lacks an object store, and its one Redis node accepts cross-slot commands production rejects: how does it match production?",
 "(a) a 3-master Redis Cluster and final-upstream MinIO locally and at the release gate, plus (b) a CROSSSLOT lint.", "T3", "M0"),
("Q-KEYS-11", "How long does GKM keep epoch objects?",
 "(a) 30 days, then until every leaf acking in the last 30 days has applied them.", "§19 sizing", "M2"),
("Q-EVS-6", "Must a head reader that does not replay verify per-file freshness?",
 "(a) no in v0, measuring how often phones read files older than the 64-version window.", "format 1, since (b) changes `EvsPush`", "M2"),
("Q-OPS-2", "Should small objects pack? Y2's HDD mix needs ~32,000 drive operations a second against ~8,000-12,800 (19.6), and gkm's `gen/` takes the metadata tier to ~5 sets by count (19.9).",
 "(b), §11's 16 KiB inlining and debouncing, for segments in v0; (a) packing once drive operations pass half §22.8's rate; (a) for `gen/` before Y2.", "§11's locator format (M2); the Y2 pools (D-OPS-17)", "M2"),
("Q-BRIDGE-2", "How do bridge links reach targets: a multi client per target, or a link on the subject's own client?",
 "(c) a client per target now; own-client links where memory demands, the iOS tunnel first.", "link code, the iOS bridge", "M4"),
("Q-SDK-5", "Where does the iOS device role's code live, given that a root-package role links every root init and `protocol` descriptor into the extension?",
 "(a) the root if M4's measurement passes §4's 1 MiB gate, else (b) a leaf `sidecar/device`.", "the iOS device role (M4's seam)", "M4"),
("Q-OPS-5", "Should `dns` deploy staged (`--only-older`, stopping at 25%) or in one pass like `dnsedge`?",
 "(a) staged.", "19.11's classes (M5)", "M5"),
]

INDEX_INTRO = (
"Every entry of the owner's record (owner/DECISIONS.md), by number: 1-111 from the interview of 2026-11-03, 112-125 "
"from the follow-up of 2026-11-04. \"Settles\" names the X and Q- items the entry decides. The decision is one line, "
"faithful to the record; where owner/APPLY.md §2 or a later entry says another entry governs, the line says so. "
"\"Implemented in\" lists the sections whose text cites the entry as \"owner decision N\"."
)

# n | settles | decision (one line, with supersession)
INDEX = [
(1, "X12; Q-KEYS-9", "MLS ships in v0, as PLAN.md says; per-device wraps are not the v0 distributor. Its \"fork an implementation\" is superseded by @@OD:43@@."),
(2, "X2; Q-EVS-1", "Hashed path segments: keyed, parent-chained 16-byte tokens; under the final owner direction, evs and gkm are stateless over file-cluster objects (seg/, idx/, head/, push/, subs/, gkm/), with no Postgres or Redis for file storage. The earlier Postgres path index and per-ref Postgres row are superseded; item 9's path-key rotation is read together with @@OD:64@@'s lazy rewrap."),
(3, "X3; Q-ACL-1 (Q-TRUST-1, Q-TEAM-5, Q-KEYS-5 follow)", "A customer key authority signs policy and membership from v0; clients refuse what they cannot derive from signed inputs, so a breached server can only deny or delay; it subsumes the separate member-signed DeviceAdmit."),
(4, "X10; Q-CORE-1, Q-CORE-2, Q-QUOTA-4", "One encryption-required client per sidecar, a child of the device's client where one exists in the network, else top-level; declared no-egress sidecars are exempt from client caps and count in `sidecar_clients`."),
(5, "X3 mechanism", "One admin-written, signed, encrypted config repo per network holds the admin set, admissions, tags, groups, policy, bridge rules, service settings and an id-only projection for server gates; members sign their own devices' admissions, which @@OD:112@@ confirms."),
(6, "config repo read scope", "Every admitted device reads the whole config repo and evaluates its own rules; there is no always-on compiler, and the server gets the signed id-only projection."),
(7, "evs grants", "evs grants a key as reader (repo keys) or reader+writer (signed heads accepted from the writer set); membership changes come only from keys allowed to grant, which @@OD:113@@ reads as binding the change, not the committer."),
(8, "evs grant authority", "Repo admins and network admins grant, verified through the config repo's delegation chain."),
(9, "X15; Q-PHASE-1", "Two parallel tracks after the shared M0-M2; a second team builds mail and burner; mail's external lead times start in M0."),
(10, "X11; Q-QUOTA-2, Q-QUOTA-6", "All traffic bytes count toward the transfer balance (edges, shares, storage transfer, relayed same-network traffic); storage, sends, DNS entries and TLS endpoints are quotas."),
(11, "Q-QUOTA-5; Q-PROTO-3", "The dialing network pays for cross-network share traffic; edges use a new Service provide mode (C9), shares FriendsAndFamily with the source network sealed (C13)."),
(12, "X6; Q-MAIL-2", "Burner mail is received by always-on receivers only; no iOS tunnel receiver; iOS-only users receive while the app is open; no hosted or TEE receiver."),
(13, "X4; Q-DNS-1", "ur.network becomes a user-content-only root: signed, strict DMARC, PSL-listed when eligible and renewed for 3+ years; platform names and company mail move off it."),
(14, "X5; Q-DNS-2", "An opaque, random, immutable network label, with an opt-in alias equal to network_name."),
(15, "X17; Q-DNS-3", "recURd starts at ur.io/recurd on the main bringyour.com services; recurd.dev redirects; no dedicated infrastructure."),
(16, "service domain", "bringyour.com is the service domain for platform and new service names; ur.io is the web. Its \"dedicated tlsedge addresses\" are superseded by @@OD:34@@."),
(17, "X8; Q-PROTO-1", "Residents send sidecar subprotocol frames from ControlId (amending SUBPROTOCOL.md decision 6), with an HTTPS long-poll fallback in v0; pushes are hints. Stands together with @@OD:88@@."),
(18, "X13; Q-OPS-1", "A new self-hosted MinIO built from the final upstream source, behind `ServiceHost.Blobs`, with conformance tests gating upgrades; ordering in the object store. Its \"~4 SSD/NVMe hosts\" and off-site copy are superseded by @@OD:20@@, @@OD:21@@ and @@OD:94@@."),
(19, "Q-REPO-1", "All service logic is a sidecar engine behind host interfaces; server implements them, owns migrations and routes, and hosts each engine."),
(20, "file cluster", "The file cluster is 4 hosts, each with 16 × 16 TB HDDs (about 1 PB raw); @@OD:94@@ sets the topology and @@OD:116@@ the parity."),
(21, "file cluster", "A small NVMe metadata tier, 2 drives per host, run as a separate pool or cluster with its own bucket, holds index entries, heads, push logs, gkm objects and subscriptions; @@OD:116@@ moves week-old push logs onto the HDDs."),
(22, "X9; Q-REPO-2", "Approve §4.6's recommended connect changes by milestone; reject C1, C2, C6b and C10; defer C7; decide C17 after §18's spike. Amended by @@OD:85@@ (C14 into M4) and @@OD:86@@ (C18)."),
(23, "Q-CORE-6", "One daemon hosts one Sidecar per network, sharing the keychain unlock and MCP endpoint; no key links networks."),
(24, "X19; Q-EVS-2", "A local git server (http and ssh) plus `git-remote-ur`; only the sidecar talks to evs. Its \"loopback only\" is superseded by @@OD:84@@."),
(25, "X20; Q-MCP-1", "Record primitives in DESIGN.md; RECORD.md is designed separately, an M0 deliverable reviewed before storage format 1 freezes."),
(26, "X14; Q-SDK-1", "The extension runs a WASM worker, HTTPS-only first, with a native companion meanwhile; never a hosted sidecar."),
(27, "X16; Q-QUOTA-1", "PLAN's quotas; Team $100 a month for 5 billable seats, then $20 a seat; overage only on transfer and storage; replies-only dropped. @@OD:122@@ sets the overage rates."),
(28, "X18; Q-BRIDGE-1", "An IPv4 overlay: a random /16 per network, by default from 100.64.0.0/10, which admins may cycle or choose. Its \"private names (v1)\" is superseded by @@OD:85@@."),
(29, "Q-MAIL-3", "Burners live under ur.network with a label each. Superseded by @@OD:32@@."),
(30, "Q-SMTP-2", "The send quota counts outbound connections per day, with per-connection byte and duration caps and a recipient cross-check."),
(31, "X6; Q-MAIL-1", "Inbound routing by SNI with DANE. Its per-network IPv6 and Team dedicated IPv4 are superseded by @@OD:34@@."),
(32, "Q-MAIL-3, Q-MAIL-10", "Burners are `<name>@<word-number>.<net>.ur.network` under a wildcard MX to `mx.<net>.ur.network`; a network's burners are linkable through its label. Supersedes @@OD:29@@."),
(33, "X6; Q-MAIL-9", "Refuse non-STARTTLS senders with 530 and publish the deviation; Team networks may run a direct MX. Stands beside @@OD:34@@."),
(34, "addresses (Q-MAIL-1, Q-TLS-1, Q-SMTP-6)", "No dedicated IPv4 or IPv6: inbound mail routes by SNI and DANE only and the M7 SNI census gates the burner launch; tlsedge shares the lb addresses through an `ssl_preread` split on TCP 443; mxedge and smtpedge use the shared lb addresses, which @@OD:124@@ settles for smtpedge."),
(35, "X7; Q-SMTP-1", "No outbound mail until the ZK preamble proofs are sound, fast and interop-tested; burner email launches receive-only. Its external audit is dropped by @@OD:99@@, and @@OD:125@@ adds DATA coverage to the gate."),
(36, "X7; Q-SMTP-5", "Each sending sidecar holds its own DKIM key under an opaque selector, at most 64."),
(37, "Q-SMTP-3", "Tiered, domain-scoped halts; confirmed fraud or phishing halts at once on any tier; appeals restore early."),
(38, "X7; Q-SMTP-4", "Refuse unauthenticated destination MXs unless the user allows that domain; plaintext destinations are always refused."),
(39, "X1; Q-TLS-2", "Certificates by CSR proxy and DNS-01 in URnetwork zones; customer ACME accounts pinned by CAA on Team custom domains; sidecars watch CT."),
(40, "X1; Q-TLS-3", "Per-device keys and certificates for the network wildcard; scope sublabels when needed; no shared key."),
(41, "X1; Q-TLS-4", "Abuse hooks plus a verified account for Community publishes, which last at most 7 days."),
(42, "Q-TLS-7", "Published services default to network members via URnetwork login; the check runs in the sidecar's front."),
(43, "X12; Q-KEYS-1", "A narrow in-house MLS implementation in root `mls_*` files, tested against the mlswg vectors and two libraries. Its audit is deferred by @@OD:99@@."),
(44, "X12; Q-KEYS-2", "Ciphersuite 0x0010 (X-Wing hybrid KEM, Ed25519 signatures) from v0."),
(45, "Q-TEAM-1 (Q-TEAM-5 superseded)", "A staged P0 auth fix: refuse sidecar tokens on admin routes, then move sensitive routes to network-token-only, then flip all 27 AppAdmin routes."),
(46, "Q-TEAM-4 (Q-TEAM-7)", "Team SSO is OIDC only; the server keeps users, emails and roles, and the rest lives in the config repo."),
(47, "Q-TRUST-2", "The harness and its agents are inside the device trust boundary."),
(48, "Q-CTX-1", "Self-hosting comes at the later assured stage and stays possible from v0; no self-hosted bundle in v0."),
(49, "Q-MCP-4", "Cloud agents run `ur` inside the VM, reaching bringyour.com over the sandbox's HTTP CONNECT proxy; keys stay in the VM."),
(50, "Q-BRIDGE-3", "Providers refuse LAN, loopback, link-local and overlay destinations to same-network sources only in networks with an ACL document; @@OD:120@@ keeps allow-all elsewhere, disclosed."),
(51, "Q-REPO-4", "Keep the docs and code together in the sidecar repo; publish later, after a scrub. Its scrub and \"publish later\" are superseded by @@OD:117@@ and @@OD:118@@."),
(52, "Q-REPO-3", "sidecar/protocol is a test-enforced exception to the subpackage-import rule."),
(53, "Q-MAIL-4", "Opt-in burner forwarding ships with outbound mail."),
(54, "Q-MAIL-5", "Disclose that team receivers see inbound mail in transit; teams designate receivers. Superseded by @@OD:58@@."),
(55, "Q-TEAM-2", "New team networks only, in v1; no in-place conversion."),
(56, "Q-TEAM-3", "SCIM provisioning is in Team v1."),
(57, "Q-MCP-2", "Bare `ur` speaks MCP when stdin is not a terminal and prints help on a terminal."),
(58, "Q-MAIL-5", "Each team chooses designated receivers or per-member receivers with their own mail subdomains. Supersedes @@OD:54@@."),
(59, "Q-CTX-3, Q-TLS-5, Q-SOCK-3, Q-TRUST-3, Q-CORE-3, Q-ACL-8, Q-KEYS-4, Q-KEYS-12", "Answers implied by earlier entries, recorded without being asked; the gkm values of Q-KEYS-12 were confirmed by @@OD:115@@."),
(60, "X12; Q-KEYS-3", "One MLS group per evs repo; reader and writer grants map onto group membership. Amended by @@OD:114@@: member devices are leaves, and agents hold wraps."),
(61, "Q-KEYS-6", "Per-entry crypto-shredding for record-class repos and mail, in format 1."),
(62, "Q-KEYS-7, Q-CORE-5", "A recovery code plus admin re-add."),
(63, "Q-KEYS-8", "Team escrow is a visible audit member on a customer-operated device, a Team opt-in in v1."),
(64, "Q-KEYS-10", "Lazy rewrap: a full checkpoint on the first write after a removal; `ur evs rekey` on demand."),
(65, "Q-SOCK-1", "A load-aware weighted power-of-two-choices scheduler; affinity opt-in."),
(66, "Q-SOCK-2", "No caps on IP and port forwarding or sockets; only the transfer balance limits use."),
(67, "Q-SOCK-4", "Internal socket names are blinded by HMAC under a config-repo key; published names stay plaintext."),
(68, "Q-TLS-8", "Published names may use 443 plus a short fixed list of TLS ports; @@OD:121@@ sets the list."),
(69, "Q-DNS-4", "Self-hosted authoritative DNS only, with online DNSSEC signing; @@OD:123@@ keeps both nameservers at the one site."),
(70, "Q-DNS-6", "Networks edit their own records within quota; system-managed records are refused."),
(71, "dns hosting", "The dns service runs on a new edge host type with its own addresses and TCP and UDP 53."),
(72, "Q-ACL-2", "Policy is signed under the customer's key authority and stored encrypted; URnetwork enforces an id-only projection and sees the reach graph."),
(73, "Q-ACL-6", "Every tier may write access-control policies, with per-tier limits."),
(74, "Q-ACL-7", "Requested grants are approved by the owner or sponsor, an admin for wider ones; 1 h by default, 30 days at most."),
(75, "Q-MCP-3", "For single-device users, the harness's permission prompt counts as approval, labeled by evidence type."),
(76, "Q-TRUST-4 (Q-CTX-2, Q-SDK-4)", "Web pages may decrypt, clearly labeled; one browser sidecar serves every web surface."),
(77, "Q-TRUST-5", "Signed releases only; no reproducible-build gate for the end-to-end claim."),
(78, "Q-SMTP-7", "Raw attributed abuse reports are sealed unparsed to the network's mail key and kept 30 days."),
(79, "Q-MAIL-12", "Per-burner DKIM and MX records for replying burners until the PSL listing, then relaxed alignment."),
(80, "Q-MAIL-11 (Q-PHASE-2 moot)", "Email approvals are dropped from the product."),
(81, "Q-EVS-4", "Forced git identity through signed heads and local committer checks."),
(82, "Q-EVS-5", "Repo deletion is a soft delete; keys are shredded after 7 days unless restored, or at once with `--now`."),
(83, "Q-TEAM-8 (Q-TEAM-9)", "A departing member's tagged agents stay; released names are held 24 h."),
(84, "Q-BRIDGE-5", "Forwards and local service listeners bind 0.0.0.0/:: by default; `--listen` narrows. Supersedes @@OD:24@@'s loopback rule and D-TRUST-8's loopback default; the TLS-only rule off loopback awaits the owner (Q-BRIDGE-5)."),
(85, "Q-BRIDGE-4", "Private split-DNS names for overlay addresses ship with the first bridge release. Supersedes @@OD:28@@'s \"v1\"."),
(86, "Q-BRIDGE-6", "The IP path carries all forwards and invites, cross-network included, adding connect change C18."),
(87, "Q-SDK-2", "The iOS app and the desktop `ur daemon` host the sidecar; network processes hold only the keyless device role."),
(88, "Q-SDK-3", "Content-free APNs and FCM wake pushes ship in v0. Stands together with @@OD:17@@."),
(89, "Q-OPS-7", "v0 runs at one site: RPO 5 min for metadata and 1 h for segments; RTO 4 h. Its off-site replication is superseded by @@OD:94@@."),
(90, "Q-OPS-6", "No backups of key slots or wraps, so erasure is immediate."),
(91, "Q-OPS-4", "Edges and mail are tested in main, dark only; no canary stage."),
(92, "Q-QUOTA-3", "Team overage is post-paid through Stripe meters, with a credit line drawn last."),
(93, "Q-ABUSE-5", "Notify users unless an order seals the request; signed quarterly canary; no prospective collection."),
(94, "storage topology", "v0 has one site, one metadata and one storage cluster, \"2 replicas\" read as 50% parity, and no off-site copy; it supersedes the off-site parts of @@OD:18@@ and @@OD:89@@, and @@OD:116@@ confirms the parity reading."),
(95, "Q-ABUSE-3", "Automated abuse actions act at once, with human review within 24 h; business-hours staff in v0, 24/7 on-call by v1."),
(96, "Q-ABUSE-2", "Anonymous-only networks never publish names or send internet mail without verifying or paying."),
(97, "Q-ABUSE-4", "Labels, aliases and hostnames are screened at creation; probation networks have record caps."),
(98, "Q-ABUSE-1", "Disclose inbound interception risk and label each message validated or opportunistic; sidecars watch DNS and CT; a Team strict mode."),
(99, "Q-TEST-3 (Q-PHASE-5 moot)", "\"No review at the moment, just get it working\": no external security review for now; @@OD:35@@'s gate drops its audit and @@OD:43@@'s audit is deferred. @@OD:119@@ lets copy say \"end-to-end encrypted\" with this disclosed."),
(100, "Q-TEST-4", "The iOS tunnel footprint is verified with host and Android surrogates only; no physical iPhone."),
(101, "Q-TEST-7", "Fuzz targets with seed corpora run as ordinary Go tests; no continuous fuzzing host."),
(102, "Q-PHASE-4", "Before M6, each pilot developer uses a personal network; team features wait for M6."),
(103, "Q-PHASE-7", "Sidecar-held child and admin-refused tokens get a hard 7-day expiry, shipped with the P0 auth fix."),
(104, "Q-REPO-5", "Server-only engines live in child packages (`sidecar/<svc>service`) that only server imports; the ZK prover in its own nested package or module."),
(105, "Q-ACL-4", "Untagged sidecars act as app devices (today's same-network reach) until the network writes a policy; @@OD:120@@ keeps this, disclosed."),
(106, "Q-ACL-5", "In networks with a policy, legacy clients are reachable only through unrestricted grants, else source-only."),
(107, "Q-PHASE-8", "The sidecar repo goes public at the first recURd release, after the scrub; server and sdk merge their sidecar code to main then. Superseded by @@OD:117@@ (no scrub) and @@OD:118@@ (public now; every repo merges at each Gn-out)."),
(108, "Q-TRUST-6", "No dedicated recURd issuer or keys initially (implied by @@OD:15@@)."),
(109, "Q-DNS-5", "ur.network is DNSSEC-signed from the dns edge's first deploy and soaked before inbound mail relies on DANE."),
(110, "Q-TEAM-6", "One admin signature admits a sidecar or member; admin-set and authority-key changes need k-of-n admin signatures. Read with @@OD:112@@: a member's own device admits the member's new device alone."),
(111, "Q-MAIL-6", "mxedge rejects at the greeting only for high-confidence botnet and exploit listings; it never greylists."),
(112, "Q-TEAM-10 (Q-KEYS-5)", "A member's own admitted device admits that member's new device alone, as a scoped delta, unless `self_admit` is off; an AdminSet member's new device still needs k of n, its existing device counting as one; this subsumes §10's DeviceAdmit."),
(113, "Q-KEYS-13", "The phrase \"only from keys allowed to grant\" in @@OD:7@@ binds the change, not the committer: any writer leaf commits an Add or Remove that a signed grant, admission or revocation requires, members reject one without it, and D-KEYS-7 is withdrawn."),
(114, "Q-ACL-9 (X12)", "Tagged, ephemeral, CI and cloud sidecars read and write through per-generation X-Wing wraps, not MLS leaves, amending @@OD:60@@; agents read once a grant exists and leave the 1,000 leaves to members; wrapped writers rotate but never commit Removes, and revoking an agent is a generation not wrapped to it."),
(115, "Q-KEYS-12 (X12)", "gkm's visible values per §10.6's rows are confirmed: ciphertext plus group id, epoch, sizes and the listed sidecar ids, so membership shows as sidecar ids; never a proposal, credential change, ratchet tree or key."),
(116, "Q-OPS-1 residual (X13)", "The file cluster as recommended: EC:8 on the HDD sets (about 512 TB usable) and EC:4 on the NVMe tier, 3.84 TB NVMe drives with a pool before Y2, week-old push logs packed onto HDD (refining @@OD:21@@), a cold spare on site; the Y1 and Y2 inputs stay an estimate."),
(117, "Q-REPO-4 residual", "No scrub: the sidecar repo keeps its documents and history, and D-REPO-8 is withdrawn, superseding the scrubs of @@OD:51@@ and @@OD:107@@; its \"D-REPO-9 stands\" is superseded by @@OD:118@@."),
(118, "Q-OPS-8; Q-PHASE-8", "The sidecar repo goes public now (2026-11-04), as it is; server's and sdk's `sidecar` branches use their public remotes and merge to `main` at each Gn-out, migration groups with their milestone, and D-REPO-9's mirrors are withdrawn. Supersedes @@OD:107@@'s timing and @@OD:51@@'s \"publish later\"."),
(119, "Q-TRUST-8", "Product copy says \"end-to-end encrypted\" now; the security page discloses that the cryptography is not independently audited, and pitch5's audit-before-claim line changes."),
(120, "Q-TRUST-7", "Keep allow-all and disclose it: without a policy, sidecar sources keep same-network reach to LAN, loopback, link-local and overlay destinations (@@OD:50@@ and @@OD:105@@ stand); I-10 is amended to that scope."),
(121, "Q-TLS-8 residual", "The published-port list is 443 plus 8443, 8883 and 5671, each a permanent lb port on the shared addresses."),
(122, "Q-QUOTA-1 residual (X16)", "Overage uses existing rates: transfer at the data-pack rate ($3/TiB) and storage per GiB-month from the cluster's cost per usable TB, reviewed yearly, with prices in pro.yml."),
(123, "Q-DNS-7", "Two nameservers at the one site only, with no off-site NS; a site or Hurricane Electric outage stops every ur.network name, ACME DNS-01, DANE and inbound mail until restored, an accepted risk."),
(124, "Q-SMTP-6", "smtpedge sends from the shared lb addresses with PTR names under bringyour.com and HELO equal to the PTR; no IP pools or per-IP warm-up; a mail listing also hitting api and connect ingress is an accepted risk."),
(125, "Q-SMTP-1 residual (X7)", "Always fund a DATA circuit: the DATA-mode proof is built beside BDAT and DATA coverage is part of D-SMTP-16's gate, superseding D-SMTP-17's accepted coverage loss."),
]

# Known gaps: section text that still contradicts an owner decision (where, text, decision, note).
KNOWN_GAPS_INTRO = (
"The assembly's checks found section text that still contradicts owner decisions. All of it states an answer or an "
"open question that the 2026-11-04 entries (owner decisions 112-125) replaced, in sections or rows not edited since. "
"Each row names the place, quotes or summarizes the text, and gives the decision that governs; each needs a section "
"edit, and the sections below reproduce the text verbatim until then. A grep for the options the 2026-11-03 decisions "
"superseded (Postgres or Redis as evs or gkm state, off-site copies, WAL, external-audit or AR1-AR3 gates, dedicated "
"addresses, policy slices, Route 53 for ur.network, loopback-only git, IMAP or SMTP on loopback) finds them only as "
"current-state facts, rejected alternatives, withdrawn stubs, risk rows or departures."
)
KNOWN_GAPS = [
("§1.2 R-CTX-28",
 "\"Agents reach only granted ranges and model servers, and egress only through customer-run exits\", owned by \"§17 (Q-TRUST-7)\"",
 "@@OD:120@@",
 "Without a policy, agents keep same-network allow-all, disclosed; the requirement holds once a network writes a policy, and Q-TRUST-7 is decided."),
("§3.7 F1 notes 6-8",
 "\"Q-TEAM-10 pending\"; an agent uploads a ReaderKey \"only if the owner answers Q-ACL-9 (a)\"; \"this holds under either answer to Q-KEYS-13\"; \"Every admitted sidecar, auth-key enrollments included, becomes a leaf of the config group ... Q-ACL-9 pending\"",
 "@@OD:112@@, @@OD:113@@, @@OD:114@@",
 "Self-admission is decided; agents read the config through ReaderWraps, not leaves; who commits a config-group Add is Q-KEYS-14."),
("§3.7 F3 notes 5 and 7",
 "\"which the owner confirms at M2's entry, Q-KEYS-12\"; \"Until the owner answers Q-KEYS-13 ... only the leaves of keys allowed to grant ... commit Adds, Removes and rotations, and write ReaderWraps if Q-ACL-9 (a) is chosen\"; a later device \"waits for the next online grantor leaf\"",
 "@@OD:113@@, @@OD:114@@, @@OD:115@@",
 "Any writer leaf commits a signed change, agents hold wraps, and gkm's values are confirmed."),
("§3.7 F4 note 3; F5 note 3",
 "\"one of §13's fixed TLS ports (Q-TLS-8 pending)\"; smtpedge dials \"from the lb's shared IPv4 addresses (owner decision 34; Q-SMTP-6 pending)\"",
 "@@OD:121@@, @@OD:124@@",
 "The extra ports are 8443, 8883 and 5671; smtpedge uses the shared lb addresses with PTR names under bringyour.com."),
("§3.7 F9 (actors, notes 4-8)",
 "\"a remaining grantor's device\"; \"a grantor leaf commits the Remove\"; \"The committer rule is F3 step 5's until the owner answers Q-KEYS-13\"; \"with no grantor leaf online, writes get 412\"",
 "@@OD:113@@",
 "Any writer leaf commits the Remove a signed revocation requires."),
("§3.12; §3.13; §3.14",
 "\":147 readers and writers are leaves | kept; Q-ACL-9 (a), pending, would wrap non-member sidecars\"; \"grantor-leaf commits and leaf readers until Q-KEYS-13 and Q-ACL-9 are answered\"; the risk \"Answers to Q-ACL-9, Q-KEYS-13, Q-TEAM-10 or Q-TEAM-11 reshape F1, F3 and F9\"",
 "@@OD:112@@, @@OD:113@@, @@OD:114@@",
 "Of the four, only Q-TEAM-11 is open, now with Q-KEYS-14."),
("§4.2 R-REPO-8; §4.7 (`make check`); §4.11",
 "\"Public at the first recURd release after a business-document scrub\" (owner decisions 51, 107); `make check` fails on \"tracked paths outside D-REPO-8's allowlist\"; business material \"that owner decisions 51 and 107 scrub before RS1 (D-REPO-8)\"",
 "@@OD:117@@, @@OD:118@@",
 "The repo is public from 2026-11-04, unscrubbed, with no business-material allowlist."),
("§4.8 (To `main`)",
 "\"server, sdk, sn and build merge at RS1 (D-REPO-9) ... Before RS1, only D-PHASE-3's P0 stages reach server's and sdk's `main` ... if the owner picks Q-OPS-8 (a)\"",
 "@@OD:118@@",
 "Every touched repo merges at each Gn-out with its migration groups' SQL (§23.9), and Q-OPS-8 is decided."),
("§4.12; §4.13 D-REPO-8, D-REPO-9; §4.14 Q-REPO-4",
 "alternatives \"Rejected (D-REPO-8)\" and \"Publishes server code before RS1 | Rejected (D-REPO-9)\"; D-REPO-8 (a `urnetwork/sidecar-archive` rename and a filtered clone) and D-REPO-9 (private mirrors until RS1) still proposed; Q-REPO-4 decided by owner decisions 51 and 107, with D-REPO-8's scrub list as its residual",
 "@@OD:117@@, @@OD:118@@",
 "Both D- items are withdrawn and Q-REPO-4's residual is answered; public remotes are the decided design."),
("§4.16; §4.17; §4.18",
 "\"D-REPO-8's archive and D-REPO-9's mirrors\"; \"§23 ... holds the consumers' merges until RS1\"; the risk mitigation \"D-REPO-8's rewrite and allowlist; D-REPO-9's mirrors\"; phasing \"the scrub list and D-REPO-8's rewrite\", \"branches and mirrors\", \"publication at RS1 (M4), then the consumers' merges\", \"the scrub list blocks the first pin; Q-OPS-8 blocks early migration merges\"",
 "@@OD:117@@, @@OD:118@@",
 "As above."),
("§5.6 (Admission); §5.15",
 "tagged and ephemeral sidecars read the config \"as leaves of its MLS group (owner decision 5), or by wraps if the owner answers Q-ACL-9 (a)\"; \"a config-group leaf per admitted device unless the owner answers Q-ACL-9 (a)\"",
 "@@OD:114@@",
 "Agents read the config through ReaderWraps; member devices are its leaves."),
("§14.5 (Coverage); §14.10; §14.11 D-SMTP-17",
 "\"M9 proves BDAT only ... so other MXs get a DSN\"; a DATA circuit \"Deferred to a designated-verifier prover (D-SMTP-17)\"; D-SMTP-17 \"M9 ships once the owner accepts the census-measured loss\"",
 "@@OD:125@@",
 "The DATA-mode proof is built beside BDAT and DATA coverage is part of D-SMTP-16's gate; D-SMTP-17 is superseded."),
("§14.12 Q-SMTP-1; §14.16",
 "Q-SMTP-1's residual \"accept the census-measured BDAT-only coverage loss, or fund a DATA circuit\"; phasing \"both circuits, BDAT only\", \"D-SMTP-17's acceptance\" and, under Later, \"a designated-verifier (VOLE) prover for phones and DATA\"",
 "@@OD:125@@",
 "Answered: always fund a DATA circuit, shipping at M9 (§23.4)."),
("§14.6 (Sending identity)",
 "`o<k>.out.<root> A <sending IP>, whose PTR is this name`; \"Pools `free` (Community) and `paid` (Pro, Team) each hold two or more addresses\"; new addresses \"ramp from about 50/day per provider\", with POOL_WARMING",
 "@@OD:124@@",
 "PTR names live under bringyour.com, as §12.7 already states, with no free, paid or burner pools and no per-IP warm-up."),
("§14.12 Q-SMTP-6; §14.9; §14.14; §14.15",
 "Q-SMTP-6 open, recommending (b) mail-only addresses; \"Prerequisites, ... due at M9's entry review: Q-SMTP-6\"; \"starts from Q-SMTP-6's v0 baseline\"; the risk mitigation \"Q-SMTP-6 (b)\"",
 "@@OD:124@@",
 "Decided (a): the shared lb addresses; the listing risk is accepted and recorded."),
("§17.6 (No document); §17.14 Q-BRIDGE-3; §17.17",
 "\"Q-TRUST-7 (b) would drop rule 4 and rule 3's first clause for marked sidecars\"; Q-BRIDGE-3's \"Residual: Q-TRUST-7 (§2)\"; the risk mitigation \"... Q-TRUST-7\"",
 "@@OD:120@@",
 "Decided (a): allow-all stays and is disclosed, so no residual remains."),
("§20.4 (tier table); §20.9; §20.12 Q-QUOTA-1; §20.16",
 "`config_admissions` \"Team 5,000 under Q-ACL-9 (a)\"; \"overage at Q-QUOTA-1's residual prices\"; Q-QUOTA-1's open residual \"what are Team's overage prices?\" for the owner; \"after 20.9's gate and Q-QUOTA-1's prices\"",
 "@@OD:114@@, @@OD:122@@",
 "Agents hold wraps, so Team's 5,000 applies, as §7.17 assumes; overage uses existing rates."),
("§21.5; §21.17; §21.18",
 "\"Under Q-SMTP-6 (a), v0's baseline ... §21 joins §14 in recommending (b)\"; risk mitigations \"Q-SMTP-6 (b)\" and \"Q-TRUST-7\"; \"M9's sending on the breakers and Q-SMTP-6\"",
 "@@OD:120@@, @@OD:124@@",
 "Both are decided: the shared lb addresses with the listing risk accepted, and allow-all disclosed."),
("§2.8 gkm-4, gkm-7 (and Appendix G)",
 "ReaderKeys and ReaderWraps \"only if the owner answers Q-ACL-9 (a)\", with \"wrapped readers (Q-ACL-9 (a))\" as their purpose",
 "@@OD:114@@",
 "§10.6's rows, which §2.8 says it adopts verbatim, read \"(owner decision 114)\"; Appendix G matches §2.8."),
]
KNOWN_GAPS_NONE = ""
OTHER_GAPS_INTRO = "Other consistency gaps the checks found; each needs a section edit:"
# where | gap | effect
OTHER_GAPS = [
("§2.8 gkm-9, gkm-10 (and Appendix G)", "§2.8 says it adopts §10.6's gkm rows verbatim, but its gkm-9 omits §10.6's \"GroupInfo requests included\" and its gkm-10 \"written at most daily\".", "The published list lags §10.6 on two details."),
("§2.8 evs-1, evs-8, evs-12 (and Appendix G)", "§11.17 has §2.8 follow §11.8's key families: evs-1's lease counter, evs-8's daily renewal (§2.8 says \"renewed on every connect\") and evs-12's `/_` seal key, parts and part hashes (D-EVS-20). §2.8 has none of them.", "The published list omits the multi-part push objects `push/<repo>/<ref>/<push_id>/<k>/_` and the lease counter."),
("§9, §14, §21", "Each exceeds its OUTLINE word ceiling by more than the +10% that G0 (§23.8) allows: +10.2%, +10.7% and +10.2%. Every other section but §3 exceeds its ceiling within 10%, which G0 accepts when the section states why.", "G0 fails for these three until they are cut or the overage is justified."),
("§9.13 Q-SOCK-3; §21.14 Q-ABUSE-1", "Both open with an X tag ([X11], [X6 residual]) outside the owning sections of X11 (§20) and X6 (§15); CONVENTIONS §7 reserves the tag for the owning item.", "None for the design; the X table uses Q-QUOTA-2 and Q-MAIL-1."),
("§1.12 D-CTX-2; §1.15", "D-CTX-2 asks the assembler to add an R-CTX column to every requirements table; the assembly keeps section text verbatim.", "Appendix F traces by PLAN.md line instead."),
]


# Order the open and peer-review rows by the milestone that needs them (§23.6).
def _mkey(r):
    m = re.search(r'M(\d)', r[4])
    return int(m.group(1)) if m else 99
import re
OPEN_OWNER = sorted(OPEN_OWNER, key=_mkey)
PEER = sorted(PEER, key=_mkey)
