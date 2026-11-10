## 21. Abuse, safety, and legal process

### 21.1 Purpose and scope

This section sets abuse policy: mail reputation, hosted-content and name abuse, network standing, intake and appeals, legal process and transparency. Mechanisms and default caps stay with their owners (§8-§20); §2.8 holds the metadata list and TTLs. No control acts on content (CONVENTIONS §0).

### 21.2 Requirements

| id | requirement | source |
|---|---|---|
| R-ABUSE-1 | Reports against a message halt the network's sending for a day | PLAN.md:91 |
| R-ABUSE-2 | Servers see only ciphertext and small header values, except D-SMTP-19's report and role-mail intake (§2.8 mx-4; D-TRUST-4) | owner directive 2026-11-03 |
| R-ABUSE-3 | Public names are explicit, authenticated by default and short-lived; no agent control panels | sidecar/design/pitch5.html:698 |
| R-ABUSE-4 | Gmail spam rate under 0.10%, never 0.30% | server/EMAIL1.md:109 |
| R-ABUSE-5 | Every retained field has a purpose and TTL; holds name accounts, carry a statutory kind and deadline, are counted, never block users' shredding and silently defer drops' deletions | D-TRUST-7; owner decisions 133, 184; 18 U.S.C. §2703(f), §2258A(h) |
| R-ABUSE-6 | No client IP is logged; no client token administers | I-13, I-6 |
| R-ABUSE-7 | A dated warrant canary is published with "end-to-end encrypted" | sidecar/design/pitch5.html:933; owner decision 119 |

### 21.3 What exists today

- Server has no abuse intake, case store, network suspension or takedown path (grep, 2026-11-03).
- `ValidateNetworkName` checks only length and `[a-z0-9-]`, so `paypal-support` passes (server/model/network_model.go:178-205).
- Creation allows 5 networks per 24 h per keyed /29 or /56 (server/model/network_create_rate_limit.go:11-12; server/ip.go:84-97); guest, wallet and seed-phrase sign-ins are anonymous (server/model/auth_model.go:34-43).

### 21.4 Principles and categories

Principles (D-ABUSE-1):
1. Act on names, metadata, rates and reports at the smallest unit (host, sending domain, label, network), never the root.
2. Count every routed name as public: modified sidecars skip sidecar-side controls (§13.7).
3. Machines act at once, only on 21.8's signals; each action holds until reviewed within 24 h, in business hours in v0 (owner decisions 95, 134).
4. Each action is an appealable §8 hard deny with a case id, notified to Owners and Admins (21.8).

| Category | First action | Escalation |
|---|---|---|
| Spam | §14.8's ladder (owner decision 37) | 3 halts in 30 d: suspend |
| Phishing, malware, command-and-control | host kill (§13.9) or `SuspendHost` (§12); by mail, a network halt with review (§14.8) | 2nd in 30 d: label kill, mail halt; 3rd: suspend |
| Copyright | notice forwarded; a 2nd valid one in 30 d: host kill | 3 upheld in 12 months: suspend (17 U.S.C. §512(i)) |
| Exposed agent or admin panel; compromise | a protective host kill; for compromise, a halt or kill until the device and its DKIM selector are revoked | no strike |
| CSAM; threat to life | suspend; report (21.9) | legal |

### 21.5 Mail abuse and shared reputation

From M9 (owner decision 35), all networks and burners send from the shared lb addresses (owner decision 124; §14.6) under `<root>`, whose subdomains count together toward bulk status (server/EMAIL1.md:115). Above §14.8's per-domain and per-network halts, breakers guard what is shared (D-ABUSE-2):

| Trigger (trailing 24 h) | Action | Clears |
|---|---|---|
| `<root>` Postmaster spam rate ≥0.10% two days running, or feedback-loop complaints ≥0.10% of recipients | restricted networks pause; Community caps halve | 3 days below 0.08% |
| Either measure ≥0.20%, or a sending address on Spamhaus SBL/CSS or SNDS red | Community pauses (HALTED, queues held); the listed address leaves the sending set, not ingress, within the feed refresh, with no drain target (§14.6; owner decision 124) | delisting, then 3 clean days |
| ≥0.30% | Community and Pro pause; trusted Team continues | owner |

Breakers act early: `<root>` cannot be replaced, and listings also block platform ingress (21.17).

### 21.6 Hosted content, names, certificates

| Control | Policy |
|---|---|
| Kill switch (§13.9) | host, then label (21.4), then revocation (`cessationOfOperation`, https://letsencrypt.org/docs/revoking/) and no renewal (§13.8); an abuse kill is lifted only through its case, never by a restore (21.10); a quota downgrade's suspension of standing names (§20.7) is no §21 action |
| Proactive check | published hosts and user record names, hourly, against Web Risk's locally matched Update API (https://docs.cloud.google.com/web-risk/docs/overview); Safe Browsing is non-commercial only (https://developers.google.com/safe-browsing) |
| CT watch (owner decision 41) | the abuse worker sends 21.8 any name under `<root>` in CT that `ScreenName`'s current lists refuse; D-TLS-8 covers mis-issuance |

**Names (owner decisions 14, 97).** Brands enter only through aliases, record owners, published hosts (`paypal-login.<net>.<root>`) and burner From domains. `ScreenName` applies §12.5's rules at creation: listed brands are denied unless the network verified the brand's domain (§7.6); brand-plus-keyword names (`login`, `secure`, `verify`, `account`, `support`, `wallet`, `update`) go to review, refused on probation; word-number names stay burners' (§12.7). §15.9's word list skips `ScreenName`'s lists. smtpedge screens declared From domains, burners' included (§14.5; owner decisions 32, 79).

### 21.7 Network reputation and probation

`network_abuse_state` feeds §8's hard deny and the §12-§15 gates (D-ABUSE-4).

| State | Entry | Effect |
|---|---|---|
| probation | under 7 days old | same-network mail deposits only (D-SMTP-14); 1 endpoint, publishes ≤24 h; ≤5 user RRsets (`probation_dns_entries`), none A, AAAA or CNAME; no names held for review, aliases or outbound shares |
| standard | 7+ days old; 30 days without action | tier defaults (§20); internet mail 24 h after `POST /mail/enable` (§14.7) |
| trusted | Team with a verified domain, paid 30 days, clean 90 days | Team thresholds (§14.8); brand use |
| restricted | a network halt or a kill within 30 days | probation limits; internet mail resumes after the halt at Community caps |
| suspended | §8 suspension, until reviewed | no reach, publishing or sending; data kept, readable and exportable |

**Verification (owner decisions 41, 96).** Public names (§12.8, §13.9) and internet mail (§14.7) always need `network_verified`: a payment method (an in-window paid `transfer_balance` row, server/db_migrations.go:1653-1655) or the owner user's verified phone or email, Apple and Google sign-ins counting (server/db_migrations.go:2131-2156); api caches it like Pro (server/model/pro_model.go:164).

**Limits.** Beyond the states above and 21.5's breakers, §21 tightens a network's limits only through `network_sidecar_limit` rows citing its case, none for forwarding or sockets (§20.5; owner decision 66), and never `evs_closure_bytes_per_day` below its fixed 4 MiB floor: each eraser keeps its own allowance, so erasure stays possible at the storage limit, waiting at most as §11.13 and §15.7 state (§20.7; owner decision 146). The abuse worker opens a case, with no machine action, for a network whose closure bytes taken at the storage limit grow its stored bytes past it (§20.7); review may tighten its erasers' allowances to the floor and its `config_statements_per_day`, which bounds the admissions, each a new eraser, that a day adds (§7.9's append limits, revocations exempt). Abuse of the team directory's access requests stays inside the network: §20.4's `directory_requests_*` and `directory_target_pending` limits and a directory admin's moderation (§16.11) handle it, since the server sees no request's content; §21 may tighten those limits the same way.

### 21.8 Intake, triage, appeals

**Intake** (D-ABUSE-5). `abuse@<root>`, `postmaster@<root>` (RFC 2142) and §14.8's reports to `<token>@rpt.bringyour.com` reach `rpt.bringyour.com`'s platform listener, SNI or not (D-SMTP-19, D-MAIL-10); a network's own `abuse@` reaches its admins (§15.8). Also: a form and a law-enforcement address on ur.io, feeds, and registrar, registry and Search Console notices.

**Header-only parsing** (owner decision 78). Report and role mail get §14.8's parse and sealed copy or are dropped unread; an auto-reply points senders to the form, which takes URLs and header blocks.

**Pipeline.** Each report becomes an `abuse_case`, joined to a network by host or address (§12's label map; a burner address names its `<net>`), headers (§14.8) or edge `connection_id` (24 h); third-party data is dropped after the join, except a reported URL's path and query, which the case keeps until its first review ends, at most its review clock, so that reviewers open the page reported (§13.9; owner decision 207); a reporter's address and free text are never kept, and of free text only an appeal's own reason is stored.

| Signal | Machine action | Review (v0: business hours, the action holding) |
|---|---|---|
| §14.8 high or medium join | §14.8's ladder | ≤24 h |
| Web Risk or feed hit; trusted-flagger report naming a URL | host kill | ≤24 h |
| Any registrar or registry notice about `<root>` or bringyour.com; a law-enforcement emergency notice, EU removal orders included | a host kill for a registrar's or registry's URL | pages both members of §19.8's rota at once, at any hour from M5 (owner decisions 134, 143); handled within 1 h: removal orders and registrar or registry notices by the rota, production orders and other data requests routed to counsel's out-of-hours contact (`config/<env>/abuse.yml`) |
| A report of phishing, malware or command-and-control naming a `<root>` URL | none | ≤4 business hours, every tier |
| Other | none | ≤4 business hours on probation; 72 h paid, 7 d Community |

**Notice and appeal.** Owners and Admins get the category, target, case id and an appeal link unless a sealing order (18 U.S.C. §2705(b), §3123(d)) or a CSAM case bars it. Admins appeal (21.16, §14.8), and a second reviewer decides with reasons (DSA Art. 17); reviewers never see sealed reports.

### 21.9 Legal process under end-to-end encryption

**Posture (owner decision 93).** Counsel reviews each order. Affected Owners and Admins hear of a request before production unless a sealing or nondisclosure order bars it (18 U.S.C. §2705(b)), and after it lapses. No prospective-collection capability is built, so pen register and trap-and-trace orders (§3123) reach only retained data. Through an EU addressee, production orders (Regulation 2023/1543, applied since 2026-08-18) need data within 10 days, 8 h in emergencies (https://www.reedsmith.com/articles/eu-e-evidence-new-service-provider-obligations-from-18-august-2026/), and their issuer informs the user (https://www.crossborderdataforum.org/analysis-eus-recently-adopted-e-evidence-regulation/), so counsel decides on URnetwork's own notice; terrorist-content removal orders need action within 1 h (Regulation 2021/784 Art. 3(3), https://eur-lex.europa.eu/eli/reg/2021/784/oj). Out of hours, 21.8's pager meets the 1 h with the kill switch and the 8 h through counsel's out-of-hours contact.

**Production** reaches only §2.8's rows while retained, never content, keys, internal names or paths (§2.5), notably:
- accounts and identities (api-1, api-5), the projection's reach graph (api-7) and abuse cases (api-14);
- connect-1's contract pairs (client ids, bytes, times), for the horizon connect-1 states;
- evs's push history (sidecar ids, times, path tokens, padded sizes; evs-4, evs-12, evs-14), kept for the repo's life by default, DROP statements included: who, when, which token paths and how many versions (evs-12); its drops', drop jobs' and dry runs' state for 30 days after each ends (evs-28) and its 7-day request log (evs-7); gkm's membership as sidecar ids;
- edge records for 24 h (tls-3, with keyed visitor-address hashes; mx-2, with no sender address) and, from M9, send records for 30 days (smtp-3).

It never reaches relay frames or dials (connect-2), inbound sender addresses (mx-2), client addresses (I-13) or DNS queries (dns-2). A compelled URnetwork could, from then on, log client, visitor and resolver addresses (connect-3, tls-2, dns-2) and use §2.8's EX1-EX8, notably EX3 outside Team strict mode (owner decisions 98, 135), but add no reader against customer signatures (§2.7).

**Preservation holds (owner decisions 133, 184).** A hold keeps one network's in-scope records existing at placement until its kind's deadline (§2703(f): 90 days, renewable once; §2258A: 1 year), and collects nothing new. TTL sweeps skip those rows; `copied_rows` copies what drops or is overwritten on its own: rows of partitions that drop whole (tls-3, smtp-3, mx-2) and the Redis soft state existing at placement (evs-8's lease fields, gkm-10's acks; owner decision 136); and api mirrors each hold as `hold/<network_id>/<case_id>/_` on the first metadata cluster (§11.8; owner decision 145), so §11.13's GC and §10.6's reconciler skip in-scope objects on every cluster, and evacuation moves a held network's batched records, a shredding repo's included, into packs and parcels that nothing deletes while the hold stands (evs-19). A drop of a path's history (§11.7) whose targets a hold covers still commits: it reads, lists and bills as finished, as an unheld drop would, and its dropped versions are served to no one, while its deletions wait until every covering hold has ended (§11.13); no answer, listing or bill tells the network that a hold exists, so a sealed order stays sealed (owner decision 184). A site loss voids what a hold kept on the file cluster, which has no off-site copy (owner decision 94); §19.10's restore returns its rows and tells counsel.

```text
abuse_legal_hold(network_id, case_id, part, kind, scope, expire_time, copied_rows)
part     the primary key is (network_id, case_id, part): part 0 is the hold itself, and parts 1 and up each
         hold at most 16 MiB of compressed rows in copied_rows, so a busy network's tls-3 rows fit 21.16's
         seven tables
kind     preserve_2703f  90 d from placement, renewed once for 90 d by a renewed request (18 U.S.C. §2703(f)(2))
         report_2258a    1 year from the NCMEC report (18 U.S.C. §2258A(h)); not renewable here
overlap  holds over one scope keep it until the latest expire_time; expiry resumes TTL sweeps, GC, held shreds
         at §11.12's phase 5 and held drops' deletions (§11.13)
always   users' --now, the 7-day timer and per-entry erasure proceed under every kind, destroying keys; a hold
         keeps only the ciphertext they leave (owner decision 133; §11.12's phase 4); a drop, even with now, is
         not user-initiated shredding: a hold defers its deletions (owner decision 184)
counsel  before holds ship (M5), confirms each kind's applicability and owner decision 133's condition: that
         deleting wrapped keys to ciphertext URnetwork cannot read is permitted
```

**Copyright and child safety.** The edges are §512(a) conduits: host notices follow 21.4's ladder (§512(i)); evs notices go to the network. A §512(c)(2) agent is registered and renewed every 3 years (https://www.copyright.gov/dmca-directory/). On actual knowledge, CSAM goes to NCMEC, with no duty to scan (18 U.S.C. §2258A(a), (f)); a report places a `report_2258a` hold.

### 21.10 Retention and access

§2.8's list is the only TTL table (D-ABUSE-7): cases, actions and appeals stay 13 months after their case closes, legal requests, productions and `abuse_access_log` 3 years, holds until their kind's deadline (21.9), `network_abuse_state` only while current. An `abuse` role, separate from ops, looks up only by case id or join key, never in bulk; each read writes `abuse_access_log`; productions need legal and engineering sign-off.

**Restore.** A Postgres restore returns §21's tables, `network_tls_suspension`, zone and host suspensions and halts to the sidecar dump's age (§19.10); it lifts no recorded action:

```text
record   each action (kill, zone or host suspension, halt, §8 suspension, limit tightening) and each lift
         is sealed to a vault-held HPKE key in api and mailed, as it commits, to the abuse mailbox
         (config/<env>/abuse.yml), as {action_id, case_id, category, network_id, kind, target, until, time};
         kept as api-14's actions; each hold placed goes the same way to the legal-request mailbox, kept
         until its expire_time; both mailboxes sit at one provider outside URnetwork's Postgres and clusters,
         which the owner names, so it and SES see only each record's sender, time and size (owner
         decision 208)
restore  §19.10's abuse step, after the dumps load and before the token exchange reopens, the edges read
         the restored rows or §12.6's restore step builds the zone: the abuse role (§19.8's rota, at any
         hour) re-applies, in mail order and idempotently by action_id, every unexpired action and every
         lift mailed after the dump, each opened with the vault key, re-creating its case under its id
check    §12.6's step flags restored RRsets of networks with open cases; the abuse role clears each flag
gap      an action committed in the seconds before the primary's loss, its mail not yet sent, is lost
         with it; tlsedge still keeps a kill that Redis holds (§13.9), and feed and Web Risk hits recur
```

### 21.11 Transparency

A semiannual report counts requests by instrument and country, accounts affected, productions, holds, sealing orders, DMCA notices, abuse actions, appeals, NCMEC reports and root incidents. ur.io publishes the signed, dated quarterly canary (sidecar/design/pitch5.html:933) and the report template with "end-to-end encrypted" (owner decision 119; §23.8), and from M5, with `rpt.bringyour.com`, the RFC 3207 deviation that §15.4's 530 links (owner decision 33).

### 21.12 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| A URnetwork warning page on user names; parsing report bodies | clearer to visitors; richer evidence | edge termination under a URnetwork key (PLAN.md:84), blinding the CT watch; user mail in URnetwork memory | ruled out (owner directive) |
| Content scanning in the sidecar | catches CSAM and phishing | breaks "private from us"; server-steered lists | rejected |

### 21.13 Decisions proposed

**D-ABUSE-1 (proposed).** Controls act only on names, metadata, rates and reports (21.4). *Why:* the directive; modified sidecars skip sidecar-side controls.

**D-ABUSE-2 (proposed).** 21.5's breakers guard `<root>` and the shared addresses, with thresholds in pro.yml `sidecar_abuse:`. *Why:* reputation is shared (owner decision 124), and per-network rates stay below Gmail's feedback thresholds ([R:ext-email-zk] §2.8, §2.9).

**D-ABUSE-3 (proposed).** Takedown follows 21.6 and 21.8, within 1 h for public phishing or malware 21.8's signals confirm, and for paged removal orders and registrar or registry notices; `<root>` is verified in Search Console. *Why:* a registrar suspension, required for phishing since 2024-04-05, takes "all third-level domains" (https://www.icann.org/en/contracted-parties/advisories/documents/advisory-compliance-with-dns-abuse-obligations-in-the-registrar-accreditation-agreement-and-the-registry-agreement-05-02-2024-en), so every registrar or registry notice pages; passthrough leaves only connection refusal.

**D-ABUSE-4 (proposed).** Screening, standing and verification follow 21.6 and 21.7. *Why:* these are a brand's only ways in; Sybil networks are cheap.

**D-ABUSE-5 (proposed).** Intake and appeals follow 21.8, report mail never touching the SNI router. *Why:* reporters without SNI must deliver; the directive; AUTHZ1; DSA Art. 17.

**D-ABUSE-6 (proposed).** Legal process and holds follow 21.9 (owner decisions 93, 133), each hold with its statutory kind and deadline. *Why:* a request reaches only what retention keeps; a hold revives no shredded key; one generic hold cannot carry §2258A's 1-year preservation.

**D-ABUSE-7 (proposed).** Retention, access, restore and transparency follow §2.8, 21.10 and 21.11. *Why:* D-TRUST-7; expired keys protect users even from a compelled URnetwork; a dump-age restore must lift no action.

**D-ABUSE-8 (proposed).** Holds defer drops silently: a covered drop commits and reads as finished, and its deletions wait for every covering hold to end (21.9). *Why:* owner decisions 93, 133 and 184; a refusal would tell a repo admin that a sealed hold exists.

### 21.14 Open questions

**Q-ABUSE-1.** How far is §2.8's EX3 narrowed? **Decided by owner 2026-11-03 (owner decision 98):** (c): per-message labels (I-11), DNS and CT watches, and §15.4's Team strict mode. *Residual:* none; owner decision 135 defines "validated" (§15.5).

**Q-ABUSE-2.** Do anonymous-only networks leave probation without paying? **Decided by owner 2026-11-03 (owner decision 96):** yes, but public names and internet mail need `network_verified` (21.7). *Residual:* none.

**Q-ABUSE-3.** May machines act alone, and who staffs review? **Decided by owner 2026-11-03 (owner decision 95):** (a): machines act at once, people review within 24 h; business-hours staff in v0, 24/7 on-call by v1 (21.18). *Residual:* none.

**Q-ABUSE-4.** May screening and probation limit PLAN.md:25's "owns all entries"? **Decided by owner 2026-11-03 (owner decision 97):** (a): screening at creation and probation record caps (21.6, 21.7). *Residual:* none.

**Q-ABUSE-5.** What legal posture? **Decided by owner 2026-11-03 (owner decision 93):** (a): 21.9's posture and 21.11's canary. *Residual:* none; holds await counsel (21.9).

**Q-ABUSE-6.** Cross-cutting (§19.8, §23.7). How do v0's review clocks run with business-hours staff? **Decided by owner 2026-11-04 (owner decision 134):** (b): business-hours review, machine actions holding until then, plus a pager from M5 only for registrar, registry and law-enforcement emergency notices, EU removal orders included, every registrar or registry notice about `<root>` or bringyour.com counting as one (21.8); 24/7 in v1. The notices ride §19.8's out-of-hours rota, which pages infrastructure from M3 (owner decision 143). *Residual:* none.

**Q-ABUSE-7.** Cross-cutting (§11.13). How does a preservation hold apply to a drop of a path's history? **Decided by owner 2026-11-05 (owner decision 184):** (a), silent deferral: the drop commits as signed and reads, lists and bills as finished, its dropped versions served to no one and its bytes uncounted, while its deletions wait until every covering hold ends; nothing tells the network that a hold exists (owner decision 93), which refusing the drop, (b), or refusing it only under notified holds, (c), would. *Residual:* none.

### 21.15 Departures from PLAN.md

- **PLAN.md:91.** §14.8 halts a reported burner label, and networks by tiered rules (owner decision 37; Q-SMTP-3); 21.5's breakers can pause networks no report names (owner decision 95; Q-ABUSE-3).
- **PLAN.md:25 ("owns all entries").** Screening and probation refuse some labels and records (owner decision 97; Q-ABUSE-4).

### 21.16 Interfaces

- **Provides:** 21.4-21.11's policies; `ScreenName`; `network_abuse_state` and `network_verified` (§8, §12-§15); 21.7's per-network limit tightening (§20.4, §20.5); `hold/` objects on the first metadata cluster (§11.8; owner decision 145).
- **Consumes:** §12-§15's hooks (`SuspendZone`, `SuspendHost`, kill switch, revocation, label maps, joins, halts, send gate, mail key); §8 suspension; §7 roles, verified domains; §20.5's overrides and §20.7's stored and closure byte counts (21.7); §10.6's and §11.13's hold checks on every metadata cluster; §19.8's rota and pager (owner decision 143); §19.10's hold recovery and abuse step; §12.6's restore flags.
- **Subprotocol messages:** none; state changes ride §6's `core`, `sock` and `mail` hints.
- **API routes** (api, §19.4): `POST /abuse/report` (Public, rate-limited); `GET /abuse/cases` (Network, read roles); `POST /abuse/appeal` (Owner or Admin; never a client token); `GET /abuse/status` (Client, own state; sidecar-classified, on §7.4's `strict_exp` allowlist); `POST /abuse/action` (staff, off the public API; it refuses a `network_sidecar_limit` row that sets `evs_closure_bytes_floor` or `evs_closure_uploads_per_s`, both fixed, or takes `evs_closure_bytes_per_day` below the floor: §20.5, §20.7).
- **Tables** (api; migrations ≥926 in §19.7's MG5): `abuse_case`, `abuse_action`, `abuse_appeal`, `network_abuse_state`, `abuse_legal_hold` (with `kind`, 21.9), `abuse_access_log`, `legal_request`.
- **Services and config:** the taskworker abuse worker (feeds, Web Risk, the CT watch, breakers, 21.7's closure-growth cases, TTL sweeps, hold copies); pro.yml `sidecar_abuse:` thresholds; `config/<env>/abuse.yml` for feeds, Web Risk, reviewer and pager routing, the abuse and legal-request mailboxes and counsel's out-of-hours contact; a Web Risk key and the mailboxes' HPKE key in vault.
- **Assumptions about other sections:** §14 and §15 run `rpt.bringyour.com` from M5; §19.8's out-of-hours rota carries 21.8's notices from M5, paging both members at once, and review runs 24/7 from M6; §19.10 restores holds' rows, re-places later holds, tells counsel and runs 21.10's abuse step in 21.10's order, and §12.6's restore step flags restored RRsets of networks with open cases; §2.8's header and api-14 publish `copied_rows` (tls-3's, smtp-3's and mx-2's rows, evs-8's lease fields, gkm-10's acks), and mx-2's, evs-8's and gkm-10's ttls except a hold's copy; api-14 lists both mailboxes' sealed copies (21.10); §11.13 moves a held shredding repo's batched records, and §11.12 resumes its shred at phase 5 when the hold ends; §11.13's drop job rereads `hold/` before each batch of deletions and defers a covered drop's deletions until every covering hold ends, the drop reading, listing and billing as an unheld one (owner decision 184); §16.11's daemons and readers apply the directory's request limits as `GET /sidecar/limits` gives them, §21's rows included (§20.4); §23.7 tracks counsel's confirmation of owner decision 133's condition and of each hold kind's applicability (`preserve_2703f`, `report_2258a`); §22 tests sweeps, access logs, holds beside shredding, a held --now shred's batched records packed, kept until the hold ends, then deleted (FS-6), hold kinds' deadlines (FS-48), clocks across a weekend (FS-49), held drops (FS-92) and, at M5, FS-39's report-intake cases and S7's SNI-less `abuse@<root>`.

### 21.17 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Safe Browsing flag (statichost.eu, 2025-09-25: https://www.statichost.eu/blog/google-safe-browsing/) or registrar hold on the root | Medium | Critical | 1 h kills, Web Risk, Search Console, the pager, a user-only root (owner decision 13), the PSL later |
| Off-hours, a wrong kill holds until business hours, about 63 h over a weekend, and unpaged signals, a Search Console flag included, wait (owner decision 134) | Medium | High | 21.8's signals only; appeals; 24/7 in v1 |
| Counsel rejects owner decision 133's condition or a hold kind | Low | High | asked before holds ship (M5) |
| A drop used to destroy evidence before a hold arrives | Low | Medium | the 7-day window keeps every byte for a hold to cover (owner decision 183); `now` drops stay visible in push history (evs-12); held drops delete nothing (owner decision 184) |
| False reports | Medium | Medium | reporter classes, host-level first, appeals |
| Free Sybil networks | High | Medium | probation, verification, the send gate, creation limits, label-scoped halts |
| A shared lb address is listed, for mail or a user name's phishing (§13.16), also blocking api and connect ingress there; with no separate mail pool to drain to and no warm-up (owner decision 124), enough listings degrade sending and the shared api and connect ingress together (accepted) | Medium | High | breakers; the address leaves the sending set (§14.6); per-domain and per-network reputation; 1 h kills; delisting |
| Without a policy, untagged sidecars and their agents reach providers' LAN and loopback (accepted, disclosed; owner decisions 50, 120) | Medium | High | §2.18's disclosure; policies on any tier (owner decision 73); suspension |

### 21.18 Phasing

- **v0 (M5), before any public name:** 21.6-21.10 with `rpt.bringyour.com` and 21.11's RFC 3207 deviation, less the later items below; the DMCA agent; Search Console and registrar contacts; business-hours review, with 21.8's notices on §19.8's rota (owner decisions 134, 143); holds once counsel confirms (21.9). **v1 (M6):** 24/7 review; tightening the team directory's request limits (21.7).
- **M7:** reporters in the census (D-MAIL-9). **M8:** trusted flaggers. **M9** (owner decisions 35, 124): §14.8's ladder, the send gate and 21.5's breakers. **M10** (v1's format 2, owner decision 169): holds defer drops' deletions (§11.13).
- **With "end-to-end encrypted" (§23.8):** 21.11's trust documents; the first report six months after the first public name.
- **Blocking:** M5's names wait on intake, the report host, the kill switch and the pager; holds on counsel; M5's exit on FS-39's report-intake cases, FS-48, FS-49 and S7's SNI-less `abuse@<root>` (§22.7, §22.8); M9's sending on the breakers.
