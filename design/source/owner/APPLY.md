# Conformance pass rules (2026-11-03, after the owner interview)

The owner answered 111 questions (owner/DECISIONS.md). Two fix rounds have already edited the 23 section files toward those answers. This pass verifies that every section implements every decision, removes what contradicts them, and gets the document ready for human peer review. These rules bind every auditor and editor in the pass.

## 1. Precedence

1. Owner decisions in `owner/DECISIONS.md`, read through the supersession table in §2 below.
2. CONVENTIONS.md §0 (the end-to-end-encryption directive) and §1 (owner rules).
3. The rest of CONVENTIONS.md: template, ids, style. Where its §4 naming registry, §7 X registry or §8 key facts conflict with an owner decision, the decision wins. For example, every X item is now decided, and the per-network mail host is `mx.<net>.<root>`.
4. PLAN.md.

Never re-open an owner decision. If a decision causes a real technical problem, keep the decided design. State the problem with evidence in Risks, and raise or extend an owner Q- item with a recommendation.

## 2. Supersession: where two decisions disagree, this one governs

| Topic | Governs | Superseded |
|---|---|---|
| MLS implementation | 43: a narrow in-house RFC 9420 subset, pure Go, in `mls_*` files in the root package | 1's "fork an implementation" |
| evs state | 2's final "Owner direction" block. evs and gkm are stateless over file-cluster objects: `seg/`, `idx/`, `head/`, `push/`, `subs/`, `gkm/`. No Postgres or Redis holds file-storage state. | 2's earlier Postgres path index and the one-Postgres-row-per-ref compromise |
| Path keys on removal | 2 item 9 (rotate via an old-to-new token translation map) together with 64 (lazy rewrap). The section must reconcile them explicitly. | Any text that keeps one path key for a repo's life without saying why |
| File cluster | 20 (4 hosts × 16 × 16 TB HDD), 21 (an NVMe metadata tier, 2 drives per host, as a separate pool or cluster with separate buckets), 94 (one site; one metadata cluster and one storage cluster; "2 replicas" read as 50%-parity erasure coding, pending the owner's confirmation in Q-OPS-1; no off-site copy in v0) | 18's "~4 SSD/NVMe hosts" and "off-site copy to B2 or R2"; 89's off-site replication |
| Recovery targets | 89's RPO and RTO apply to drive and host failures only (94). Losing the site loses server-held data, and recovery comes only from devices re-seeding their local copies (90, 94). 90 stands: no backups of key slots or wraps. | Any off-site copy, WAL archive or point-in-time recovery for storage |
| Local listeners | 84: forwards and local service listeners bind all interfaces by default, and `--listen` narrows. The daemon's control channel stays a Unix socket or named pipe; local servers authenticate callers; HTTP targets keep the DNS-rebinding Host check. Engineering rule that goes with it, under the directive: on a non-loopback bind, the content-carrying listeners (git over http, IMAP, SMTP submission) serve TLS only (git may use ssh), and plaintext stays on loopback. Q-BRIDGE-5 records this rule as a residual for the owner to confirm. | 24's "loopback only"; D-TRUST-8's loopback default and I-17, for these listeners |
| Private names | 85: private names ship in v0 with the first bridge release | 28's "private names (v1)" |
| Burner format | 32 | 29 |
| Inbound routing | 34: SNI plus DANE only; no per-network IPv6; no dedicated Team IPv4; senders that send no SNI are deferred; the M7 SNI census gates the burner launch. 33's Team direct MX stands. | 31's IPv6 and dedicated-IPv4 parts |
| TLS edge addresses | 34's Q-TLS-1 (a): an ssl_preread SNI split on TCP 443 of the shared lb addresses | 16's "dedicated tlsedge addresses" |
| Outbound gate | 99 drops 35's external audit. The gate: sound by design analysis, working, fast enough on desktops, interop-tested with Gmail, Outlook and Yahoo, with TLS 1.2 coverage for Exchange Online. 43's MLS audit is deferred. | 35's "externally audited"; any AR1-AR3 or "audited" milestone gate |
| Team receivers | 58: each team chooses designated receivers or per-member receivers | 54 |
| Admission | 110: one admin signature admits a sidecar or member; changing the admin set or authority keys needs k-of-n. 5 stands as well: members sign admissions of their own devices. Q-TEAM-10 asks the owner to confirm the self-admission path. 3 subsumes the separate member-signed DeviceAdmit mechanism (Q-TRUST-1, Q-TEAM-5, Q-KEYS-5). | Server-held authority logs; server-compiled policy slices |
| Policy distribution | 5, 6, 72: every admitted device reads the whole config repo and evaluates its own rules; servers enforce a signed id-only projection | PLAN.md:119's server-stored, server-compiled rules |
| Push | 17 (ControlId-sourced hints plus an HTTPS long-poll fallback) and 88 (APNs and FCM wake pushes in v0) both stand | — |
| gkm visibility | 59 (Q-KEYS-12): gkm sees ciphertext plus group id, epoch and sizes. This was implied, not asked, so the owner confirms it at M2's entry. | Any cleartext roster field in gkm headers |

## 3. Notation (keep the document's existing notation)

- `<root>` is the user-content root, ur.network (owner decision 13). `<net>` is the network's opaque immutable label (14), or the opt-in alias where the user chose one. `<blabel>` is a burner's generated word-number label, so a burner address is `<name>@<blabel>.<net>.<root>` (32). Burners use a wildcard MX `*.<net>.<root> MX 10 mx.<net>.<root>`, DANE TLSA at `_25._tcp.mx.<net>.<root>`, and SNI `mx.<net>.<root>`.
- A wildcard owner name carries no CNAME (RFC 1034 §3.6.2, RFC 2181 §10.1). Wildcard A and AAAA records (the shared lb addresses) sit beside the wildcard MX.
- Platform and service names live on bringyour.com (16). ur.io is the web. recURd runs at ur.io/recurd, and recurd.dev redirects there (15).
- The bridge overlay is a random IPv4 /16 per network, drawn from 100.64.0.0/10 by default (28).

## 4. Editing rules

- **Delete superseded text; do not annotate it.** A superseded D- item becomes a one-line stub: `**D-CODE-n (withdrawn).** Superseded by owner decision N: <one line>.` Keep every id stable and never renumber.
- **Decided Q- items** keep their id and read: `**Q-CODE-n.** [Xn] <question> **Decided by owner 2026-11-03 (owner decision N):** <decision>. <consequences, 1-3 sentences>. *Residual:* <open sub-question with its id, or "none">.` Keep the options not chosen only as one short clause, if a reviewer needs it.
- **Moot or implied items** read "Decided by owner 2026-11-03 (implied by owner decision N)". The open items that should close this way are Q-CTX-1 (48), Q-CTX-2 (76), Q-CTX-3 (59) and Q-ACL-8 (59, moot).
- **Citations.** Cite owner decisions as "owner decision N"; the assembler links them. Never cite reviewer ids in section text: RUL-n, CR-n, CONS-n, SEC-n, E2EE-n, ARCHR-n, GRD-n, READ-n, PLAN-n, critic numbers. State the substance instead.
- Put every placeholder (`<net>`, `<root>`, `<env>`, `<svc>`, `<me>`) inside a code span. HTML renderers drop bare angle brackets.
- Use no daggers (†, ‡) and no "predates" notes.
- **Budget.** Stay at or under the section's OUTLINE ceiling, counting words outside fenced code blocks. The decided design may justify up to +10%; if you use it, say so in your return value. Cut duplication: keep content in its owning section (OUTLINE.md) and cross-reference elsewhere. Prefer tables to prose.
- Verify every code fact you add or change against the repos under /Users/brien/urnetwork, read-only. Never open key, certificate, credential or token files, and never copy secret values.
- Never use or cite the message repo.

## 5. Owner questions already open (reuse these ids; never duplicate them)

- **New owner questions:** Q-TRUST-7 (LAN and loopback default for sidecar sources without an ACL), Q-TRUST-8 (claiming "end-to-end encrypted" without external review), Q-TEAM-10 (member self-admission), Q-ACL-9 (wraps for non-member sidecars), Q-KEYS-13 (who may commit membership changes), Q-DNS-7 (an NS outside the site), Q-SMTP-6 (which addresses send outbound mail), Q-OPS-8 (how migration groups reach main before RS1).
- **Residuals needing the owner's confirmation:** Q-REPO-4 (scrub timing and list), Q-OPS-1 (erasure-coding parity, NVMe drive size, load inputs), Q-KEYS-12 (confirm gkm's visible headers), Q-TLS-8 (the extra TLS port list), Q-SMTP-1 (accepting the measured coverage loss, or a DATA circuit), Q-QUOTA-1 (overage prices).
- **Left to peer review:** Q-CORE-4, Q-KEYS-11, Q-EVS-6, Q-BRIDGE-2, Q-SDK-5, Q-OPS-2, Q-OPS-5, Q-TEST-1, Q-TEST-2, Q-TEST-6.

Raise a new owner question only for a real gap that a decision leaves, or a conflict between decisions that the table in §2 does not settle. Frame it as a crisp Q- item with options, a recommendation, what it blocks, and "*Decider:* owner".

## 6. Follow-up owner decisions 112-125 (2026-11-04): binding, apply them in every section you edit

The owner answered the open owner questions on 2026-11-04 (owner/DECISIONS.md entries 112-125). Every item listed in §5 as "new owner questions" or "residuals needing the owner's confirmation" is now decided. Mark each Q- item "**Decided by owner 2026-11-04 (owner decision N):**", and rewrite the design to match.

| Decision | Q- item | Sections to update | What changes |
|---|---|---|---|
| 112 | Q-TEAM-10 (a) | TEAM, CORE, KEYS, ACL, ARCH, TEST | A member's own admitted device admits that member's new device alone, as a scoped admission delta in the config repo. A `self_admit` setting can turn this off. An admin's device that carries admin authority still needs k-of-n, with the admin's existing device counting as one of the k. This subsumes §10's DeviceAdmit. |
| 113 | Q-KEYS-13 (b) | KEYS, TEAM, ACL, ARCH, TEST | Owner decision 7 binds the change, not the committer. Any writer leaf commits an Add or Remove that a signed grant, admission or revocation requires; members verify that signed input, and a commit without one is rejected. D-KEYS-7's admin-only committer rule is withdrawn. |
| 114 | Q-ACL-9 (a) | ACL, KEYS, TEAM, EVS, CORE, MCP, OPS, ARCH, TEST, TRUST | Non-member-device sidecars (tagged, ephemeral, CI, cloud agents) read and write through per-generation X-Wing wraps in every repo that grants them access, not through MLS leaves. This amends owner decision 60: member devices are leaves, and agents hold wraps. Agents read as soon as a grant exists and cost no commit, and they do not count against the 1,000-leaf cap. Any writer may rotate by re-wrapping. Wrapped writers cannot commit Removes. Revoking an agent means a new generation that is not wrapped to it. |
| 115 | Q-KEYS-12 confirmed | KEYS, TRUST (§2.8), PHASE (§23.6) | gkm's visible values per §10.6's rows are confirmed (owner decision 115). Remove the M2-entry confirmation residual. |
| 116 | Q-OPS-1 residual | OPS, EVS, QUOTA, PHASE, TEST | EC:8 on the HDD sets (about 512 TB usable), EC:4 on the NVMe tier, 3.84 TB NVMe drives with a pool added before Y2, push logs packed onto HDD after a week, and a cold spare chassis and drives on site. The Y1 and Y2 inputs stay an engineering estimate. |
| 117 | Q-REPO-4 residual | REPO, PHASE, CTX | No scrub. D-REPO-8 is withdrawn: no sidecar-archive, no filtered clone, no business-material path allowlist. The repo keeps its documents and history, and publishing it makes them public. |
| 118 | Q-OPS-8 (resolved), Q-PHASE-8 (changed) | REPO, OPS, PHASE, TEST, CTX | The sidecar repo goes public now (2026-11-04), not at RS1. Nothing waits for publication. server's and sdk's `sidecar` branches use their normal public remotes and merge to `main` at each milestone's exit review. D-REPO-9's private mirrors are withdrawn. Migration groups merge with their milestone, so the M3 pilot runs on production normally. |
| 119 | Q-TRUST-8 (a) | TRUST, TEST, PHASE, KEYS, CTX | Product copy says "end-to-end encrypted" now, and the security page discloses that the cryptography is not independently audited: the in-house MLS on draft suite 0x0010, the storage format and path tokens, and later the ZK proofs. pitch5's audit-before-claim line changes. No audit gates the claim. |
| 120 | Q-TRUST-7 (a) | TRUST, ACL, BRIDGE, CTX, ABUSE | Keep allow-all and disclose it. Without a policy, sidecar sources keep same-network reach to LAN, loopback, link-local and overlay destinations (owner decisions 50 and 105 unchanged). Amend I-10 to that scope, add a residual-risk row, and add a product-copy disclosure. |
| 121 | Q-TLS-8 residual (c) | TLS, OPS, TEST | The published-port list is 443 plus 8443, 8883 and 5671, each a permanent lb port on the shared addresses (§19 W7). |
| 122 | Q-QUOTA-1 residual (a) | QUOTA, OPS | Overage uses existing rates: transfer at the data-pack rate ($3/TiB, config/all/pro.yml), and storage per GiB-month from the cluster's cost per usable TB (§19.6), reviewed yearly. |
| 123 | Q-DNS-7 (b) | DNS, OPS, TRUST, MAIL, PHASE | Two nameservers at the one site only, and no off-site NS. Record the accepted risk: a site or Hurricane Electric outage takes down all ur.network names, ACME, DANE and inbound mail until restored. |
| 124 | Q-SMTP-6 (a) | SMTP, OPS, ABUSE, DNS, PHASE | smtpedge sends from the shared lb addresses, with PTR names under bringyour.com and HELO equal to the PTR. No IP pools and no per-IP warm-up; reputation is managed per domain and per network. Accepted risk: a listing also hits api and connect ingress. |
| 125 | Q-SMTP-1 residual | SMTP, PHASE, TEST, MAIL | Always fund a DATA circuit. The DATA-mode proof is built alongside BDAT, and DATA coverage is part of D-SMTP-16's outbound gate, on the mail team's critical path. This supersedes D-SMTP-17's accepted coverage loss. |

After these, the owner-level open list is empty. The only open items are those left to peer review (§5).

## 7. Follow-up owner decisions 126-135 (2026-11-04, round 2): binding, apply them in every section you edit

These answer the owner questions that the conformance pass raised. After them, no owner-decider question is open. Mark each item "**Decided by owner 2026-11-04 (owner decision N):**".

| Decision | Q- item | Sections to update | What changes |
|---|---|---|---|
| 126 | Q-ACL-10 (a) | ACL, TEAM, KEYS, EVS, CORE, SDK, TRUST, MAIL, MCP, ARCH, TEST | In owner-bound repos (author vault, mailbox, other owner-bound kinds), network admins can revoke and can add only the visible audit member (owner decision 63). Any other reader needs the member's signed consent: the member's own device or recovery key signs the admission, or the member's first device joins from an invite, or an admin-signed admission is countersigned by an `OwnerConfirm{sidecar_id}` delta from the member's device. Members' devices and grantor leaves refuse Adds to owner-bound repos without that consent; such a device is parked with approval pending. The member's devices alarm on any admission under their member_id that they did not sign. §2.10 adds the threat row "a rogue or compromised admin mints a device under a member". This closes the final critic's blocker. |
| 127 | Q-TEAM-11 (b) | TEAM, CORE, KEYS, TRUST, TEST | A recovery key counts as one signature toward k for authority statements (AdminSet and authority-key changes), behind a 72 h window in which any admin device may veto. Personal networks (k = 1) recover alone. |
| 128 | Q-KEYS-14 (a) | KEYS, TEAM, ACL, ARCH, TEST | In the config group, the leaf that signed an admission or revocation commits the MLS change it requires, even if it is not a config writer. Recovery-admitted devices self-join by external commit. Writing config records stays admin-only. |
| 129 | Q-TRUST-9 (c) | TRUST, PROTO, KEYS, TEAM, MCP, TEST, PHASE | Any admitted reader sidecar, agents included, may witness HeadCheck. Writers in shared groups alarm at 24 h and stop at `ServiceSettings.witness_bound_hours` (default 72 h, range 24-168 h, set in the config repo), which §2.8 publishes as the exposure bound for a withheld Remove. Rotations, Removes and revocations never stop. |
| 130 | Q-BRIDGE-5 residual confirmed | BRIDGE, TRUST, EVS, MAIL, TEST | Off loopback, git over http, IMAP and SMTP submission serve TLS only (git may use ssh); plaintext stays on loopback. Remove the residual. |
| 131 | Q-PHASE-7 residual confirmed | PHASE, TEAM | Only sidecar-held child and admin-refused tokens get the 7-day expiry; the sdk's window clients keep today's lifetime. Remove the residual. |
| 132 | Q-BRIDGE-7 (b) | BRIDGE, SDK, TEST | A chosen overlay /16 must lie in 100.64.0.0/10 or RFC 1918. `ur bridge block` refuses other ranges. |
| 133 | Q-EVS-7 (a) | EVS, ABUSE, TRUST, TEST | Preservation holds never block user-initiated shredding (`--now`, the 7-day timer, per-entry erasure); holds pause only the server's TTL sweeps and GC, conditional on counsel confirming. |
| 134 | Q-ABUSE-6 (b) | ABUSE, OPS, PHASE | Business-hours review, with automated actions holding until reviewed, plus an on-call pager only for registrar, registry and law-enforcement emergency notices (EU removal orders included) from M5. 24/7 on-call comes in v1. |
| 135 | Q-MAIL-13 (b) | MAIL, TRUST, ABUSE, TEST | "Validated" means REQUIRETLS, or TLSA in our signed zone for the SNI host plus a sender on a versioned list of DANE- or MTA-STS-enforcing operators, identified by FCrDNS or aligned DKIM d=. Otherwise the label is "opportunistic". |

## 8. Owner decision 136 (2026-11-04): the storage tier. Binding; apply it in every section you edit

| Section | What changes |
|---|---|
| OPS (§19.6, §19.9, §19.10, §19.16-§19.18) | The metadata cluster is 4 × 2 × 2 TB NVMe: one 8-drive set, 16 TB raw, about 8 TB usable at EC:4. Use enterprise drives with power-loss protection, at least 1 DWPD, dedicated, with free bays. Create XFS with `-i maxpct=25`, and alarm on space and inodes. Add the second-pool triggers: 50% raw, 40% inodes, or 0.5 DWPD. Restate the capacity estimate: about 44 KiB raw per small object; year one fits at 20-70% under the 24 h window. Add the engineering notes: 2 × 25 GbE per host, page-cache RAM, heal times. Packing runs daily. Update the cost-per-usable-TB basis (owner decision 122) to the new hardware. |
| EVS (§11.8, §11.10, §11.13) | Packing is age-based: each day, everything older than 24 h; under 256 KiB, at 7 days. Subscription leases move from `subs/` objects to Redis, rebuilt by clients and covered by hourly resync; recompute the operation budget without lease PUTs and LISTs on the cluster. Add a verified Redis read cache for heads and projections, with the cluster still the only commit point. |
| TRUST (§2.8) | Move the subscription-lease row to a Redis family with its TTL. Add the head and projection cache rows as Redis, with short TTLs. Restate the packing row as 24 h. |
| KEYS (§10.6) | gkm objects stay on the metadata cluster; use the new capacity in any sizing statement. |
| PROTO (§6) | Hints and subscription semantics are unchanged for clients. Leases are soft state on the server. |
| QUOTA (§20) | Storage price basis: the cost per usable TB of the new hardware (owner decision 122). |
| TEST (§22) | M2's benchmark reports bytes and inodes per object on the NVMe set and projects the fill date. Add cases for losing the Redis lease state (clients re-subscribe) and for a stale cache (readers fall back). |
| PHASE (§23) | Hardware order: 2 × 2 TB NVMe and 16 × 16 TB HDD per host, the cold spare included. The second pool is a tracked year-one item. |

| ALL storage-touching sections (owner decisions 137-139) | The initial NVMe drives are Samsung PM9A3 1.92 TB M.2 22110 (PCIe 4.0 x4; about 800k random-read and 85k random-write IOPS; 1 DWPD, about 3.5 PB over 5 years; power-loss protection): 8 drives, 2 per host, 15.4 TB raw, about 7.7 TB usable at EC:4. Use 7.7 TB in capacity statements. Year-one writes are ≤6% of the drives' limit; year two's are about 35-55%; year-one wear is about 0.85 DWPD, about 6 years. Add to OPS §19.6: homogeneous erasure sets; the initial deployment is PM9A3 only, 8 in the set plus 2-4 PM9A3 spares, with no PM963 (owner decision 139); a later pool's model is chosen when its trigger fires; a SMART check before deployment; M.2 22110 slots or adapters; airflow; year two needs about 4-8× the NVMe capacity, and expansion spreads writes (pools plus a rebalance). Add to TEST §22.8: the M2 benchmark runs on these drives, reports write IOPS, wear per day, bytes and inodes per object, and the fill date, and compares 4 KiB with 1 KiB XFS blocks. In EVS §11.13, treat small-object count as a first-class budget (for example, one upload marker per push, not per segment). |

## 9. Peer-review response rules (2026-11-04): binding for the edit pass

**Precedence.** Owner decisions (DECISIONS.md, including 136-144) > this file > `peer/orders-addenda/<CODE>.md` (T6, the PM9A3 IOPS fit) > `peer/orders/<CODE>.md` (reconciled change orders) > the briefs (`peer/T1-BRIEF.md` … `T6-BRIEF.md`) > the current section text. Where an order conflicts with a later owner decision, the decision wins, and you note the conflict in your return.

**Decisions taken after the reconciler wrote the orders**, which override them:
- **136-140 (storage tier).**
  - Packing pushes history to HDD after 24 h by age (under 256 KiB, at 7 d). This overrides RECONCILE R-15's "weekly, at most 14 d".
  - The NVMe set is 8 × PM9A3 1.92 TB (about 7.7 TB usable).
  - Leases and other soft state move to Redis, plus a verified read cache.
  - The 8 × PM9A3 endurance and IOPS budget is binding (≤ 0.8 DWPD, ≤ 50% of rated IOPS), per T6's addenda.
- **141.** Q-EVS-8 is decided as (a): D-EVS-22's tip CAS on git-mode refs is decided, not proposed.
- **142.** Q-MCP-6 is decided as (c): in a tainted run, harness evidence counts only where a `requests` rule names it.
- **143.** Q-OPS-9 is decided as (a): the out-of-hours infrastructure rota from M3.
- **144.** Q-KEYS-15 is decided as (b), not the orders' recommended (a): member devices past the first 1,000 read the config group by wraps. There is no 1,000-device cap. Write the leaf-or-wrap selection rule, the move between them, and the consequences for Removes and for owner decision 128.

**Writing rules.** Correctness first; the owner asked for maximum correctness, efficiency and performance.
- Replace text rather than appending to it, and delete what a fix supersedes.
- Put normative state machines and formats in compact fenced blocks.
- Keep prose dense. Aim for at most +25% over the section's current length, and report your word count.
- Keep ids stable. New ids follow the orders (RECONCILE.md's id allocations). Use the renamed invariant labels RV1-RV3 and WK1-WK4.
- Close each peer-review question as `PEERQ.md` says: "Closed by peer review 2026-11-04: …".
- **145.** Q-OPS-10 is decided as (b), "always a second cluster", not T6's recommended (a):
  - The metadata tier grows only by adding clusters. Each new repo and its gkm group are placed at creation by a create-only `place/<repo_id>` object on the first cluster, and all their objects stay there.
  - There are no MinIO pools, and no rebalance between pools.
  - Write the placement lookup (evs and gkm resolve and cache placement, and a repo's cluster never changes without a later move tool), the creation race (the `place/` If-None-Match decides), and the §22 tests.
  - Replace "second pool" everywhere with "next metadata cluster". T6's FS-63 two-pool test becomes a test that refuses multi-pool configurations.
