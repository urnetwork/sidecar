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
| R-ABUSE-5 | Every retained field has a purpose and TTL; holds name accounts, carry a statutory kind and deadline, are counted, never block users' shredding, silently defer drops' deletions and silently keep what a network's or client's deletion removes | D-TRUST-7; owner decisions 133, 184, 526; 18 U.S.C. §2703(f), §2258A(h) |
| R-ABUSE-6 | No client IP is logged; no client token administers | I-13, I-6 |
| R-ABUSE-7 | A dated warrant canary is published with "end-to-end encrypted" | sidecar/design/pitch5.html:933; owner decision 119 |

### 21.3 What exists today

- Server has no abuse intake, case store, network suspension or takedown path (grep, 2026-11-03).
- `ValidateNetworkName` checks only length and `[a-z0-9-]`, so `paypal-support` passes (server/model/network_model.go:178-205).
- Creation allows 5 networks per 24 h per keyed /29 or /56 (server/model/network_create_rate_limit.go:11-12; server/ip.go:84-97); guest, wallet and seed-phrase sign-ins are anonymous (server/model/auth_model.go:34-43).

### 21.4 Principles and categories

Principles (D-ABUSE-1):
1. Act on names, metadata, rates and reports at the smallest unit (host, sending domain, label, network), never a root or platform name: `abuse.yml`'s `protected_names` lists both, a target equal to a root, or equal to or under a platform name, is refused, and empty lists refuse every target (21.16).
2. Count every routed name as public: modified sidecars skip sidecar-side controls (§13.7).
3. Machines act at once, only on 21.8's signals; each action holds until reviewed within 24 h, in business hours in v0 (owner decisions 95, 134).
4. Each action is an appealable §8 hard deny with a case id, notified to Owners and Admins (21.8).

| Category | First action | Escalation |
|---|---|---|
| Spam | §14.8's ladder (owner decision 37) | 3 network halts in 30 d, of any category: suspend |
| Phishing, malware, command-and-control | host kill (§13.9) or `SuspendHost` (§12); by mail, a network halt with review (§14.8) | 2nd in 30 d: label kill, mail halt; 3rd: suspend |
| Copyright | notice forwarded; the network's 2nd valid one in 30 d: a kill of the host it names | 3 upheld cases in 12 months: suspend (17 U.S.C. §512(i)) |
| Exposed agent or admin panel; compromise | a protective host kill; for compromise, a halt or kill until the device and its DKIM selector are revoked | no strike |
| CSAM; threat to life | suspend; report (21.9) | legal |

```text
counts     an action counts toward its rung unless review lifted it as wrong, and a no-strike action never
           does; the phishing, malware and command-and-control row (threat, below) counts cases, one per
           case; spam's halts count the network's halt (mail_halt), one per row and of any category, never
           a burner label's, which §14.8's rule reads the same way; copyright counts per network, as a
           repeat-infringer policy is per subscriber: valid is any notice not lifted as wrong, upheld a
           case in review state upheld (owner decision 528)
windows    an action exactly a window's age still counts; 12 months is a calendar span
kill held  while a kill stands on a host, a threat case adds nothing, and a copyright notice is forwarded,
           an abuse_action of kind notice_forward, with no second kill; a kill that ended or was lifted
           stops this (owner decision 528)
suspended  while a suspension stands no ladder takes a second, and a CSAM or threat to life report stays
           due; once lifted, as wrong or not, what led to it still counts, but only a newer halt, upheld
           case or threat case suspends again, so a complaint with no new halt cannot undo a person's lift
targets    a threat case or an exposed panel naming only a network takes no first rung and waits for a
           person, rungs 2 and 3 still acting on the network; a label target's first rung kills that host
           name, never *; "by mail" is a sending-domain target, taking the network's mail_halt, as a
           compromise does; a certificate's revocation is no rung and no machine's, and strikes nothing
           (21.6); brand and other cases, such as 21.7's closure growth, take no ladder
```

### 21.5 Mail abuse and shared reputation

From M9 (owner decision 35), all networks and burners send from the shared lb addresses (owner decision 124; §14.6) under `<root>`, whose subdomains count together toward bulk status (server/EMAIL1.md:115). Above §14.8's per-domain and per-network halts, breakers guard what is shared (D-ABUSE-2):

| Trigger (trailing 24 h) | Action | Clears |
|---|---|---|
| `<root>` Postmaster spam rate ≥0.10% two days running, or feedback-loop complaints ≥0.10% of recipients | restricted networks pause; Community caps halve | 3 days below 0.08% |
| Either measure ≥0.20%, or a sending address on Spamhaus SBL/CSS or SNDS red | Community pauses (HALTED, queues held); the listed address leaves the sending set as §14.6 says, with no drain target (owner decision 124) | delisting, then 3 clean days |
| ≥0.30% | Community and Pro pause; trusted Team continues | owner |

**Measures (owner decision 611).** The breakers read all four: `<root>`'s daily spam rate from Google Postmaster Tools, under a service account's refresh credential in vault's `abuse-postmaster-tools.yml` (§2.8's ext-14); the SNDS file of the shared sending addresses, under its key in `abuse-snds.yml` (ext-15); the feedback-loop complaints §14.8's intake records; and the listings, matched locally against URnetwork's own sending addresses in a second copy of §15.4's feed mirror, which the same pull syncs to taskworker's host (ext-4), so no address leaves for a lookup. taskworker reads the sending addresses from `smtpedge.yml` and installs the sources at start (21.16). A Postmaster answer with no spam ratio reads as unknown, never as zero, since the API's JSON drops a zero field, so that day holds a level rather than counting toward its clearing.

Breakers act early: `<root>` cannot be replaced, and listings also block platform ingress (21.17).

### 21.6 Hosted content, names, certificates

| Control | Policy |
|---|---|
| Kill switch (§13.9) | host, then label (21.4); revocation (`cessationOfOperation`, https://letsencrypt.org/docs/revoking/) and no renewal (§13.8) only where a person's review orders it, never a machine's rung, a revocation striking nothing; a suspension keeps certificates unless its case orders revocation (21.7); an abuse kill is lifted only through its case, never by a restore (21.10); a quota downgrade's suspension of standing names (§20.7) is no §21 action |
| Proactive check | published hosts and user record names, hourly, against Web Risk's locally matched Update API (https://docs.cloud.google.com/web-risk/docs/overview), whose state lives in taskworker's memory, refetched whole on a cold start and kept by RAW diffs alone, so no row holds it (§2.8 ext-6), and against 21.16's URL feeds, each a plain-text list of URLs or hosts fetched at most 64 MiB at a time, of which only names under `<root>` are kept, the feeds and their licenses being chosen outside this design; Safe Browsing is non-commercial only (https://developers.google.com/safe-browsing) |
| CT watch (owner decision 41) | the abuse worker sends 21.8 any name under `<root>` in CT that `ScreenName`'s current lists refuse; D-TLS-8 covers mis-issuance |

**Names (owner decisions 14, 97).** Brands enter only through aliases, record owners, published hosts (`paypal-login.<net>.<root>`) and burner From domains. `ScreenName` applies §12.5's rules at creation, its reserved block to labels, aliases and scope labels alone, so a record owner or published host inside a network's zone takes, through a host screen of its own, only the brand rules here and §12.7's owner table (owner decision 419): listed brands are denied unless the network verified the brand's domain (§7.6); brand-plus-keyword names (`login`, `secure`, `verify`, `account`, `support`, `wallet`, `update`) go to review, which is a refusal with a case: the route answers 429 `QuotaRefusal{limit_key: screen_review, case_id}`, `case_id` being the refusal's optional field, a uuid set for `screen_review` alone, naming the review case it opened or joined, which clients that do not know it ignore, and a rename route's `{code, message}` result may name the case in its message (§20.7; owner decision 581), storing nothing in §12's tables and reserving nothing, and a reviewer's allow, an `abuse_action` of kind `screen_allow` naming the network and the name, which `ScreenFacts` reads, lets the caller's retry pass (§12.8; owner decision 534); on probation such a name is refused with no case; word-number names stay burners' (§12.7). §15.9's word list skips `ScreenName`'s lists. smtpedge screens declared From domains, burners' included (§14.5; owner decisions 32, 79). A published host is screened again at each registration by §13.9's `ValidateListen`, so a host refused or held for review stops at the gate with no change to its signed `GrantActivate`.

### 21.7 Network reputation and probation

`network_abuse_state` feeds §8's hard deny and the §12-§15 gates (D-ABUSE-4). A network's standing is derived: a state holds exactly while its Entry cell holds, re-evaluated at each action, at each appeal's result and daily, `suspended` ending at its review; where several hold, the first of suspended, probation, restricted, trusted and standard applies, since probation's mail rule is stricter than restricted's. Only restricted and suspended keep a `network_abuse_state` row; probation, standard and trusted derive from `network.create_time`, the tier, balances and action history, cached like Pro.

| State | Entry | Effect |
|---|---|---|
| probation | under 7 days old | same-network mail deposits only (D-SMTP-14); 1 endpoint, publishes ≤24 h; ≤5 user RRsets (`probation_dns_entries`), none A, AAAA or CNAME; no name sent to review, aliases or outbound shares |
| standard | 7+ days old, in no other state | tier defaults (§20); internet mail 24 h after `POST /mail/enable` (§14.7) |
| trusted | tier `team` with a verified `network_domain` row; its `team` grant, not its line, in window across the last 30 days with no unresolved `invoice.payment_failed`; no action in 90 days but one lifted as wrong; it falls to standard when its Team lapses, its domain stops verifying or an action ends its 90 days | Team thresholds (§14.8); brand use |
| restricted | a host, label or network kill, or a network halt, within 30 days, unless lifted as wrong; a burner label's halt, a no-strike action (21.4) and a quota suspension (§20.7) never count | probation limits; internet mail resumes after the halt at Community caps |
| suspended | 21.4's suspend, until reviewed | one `abuse_action` fans out as server state that §8.6's `hardDeny` reads, never a signed `Suspend` (I-4): a `*` kill, `SuspendZone`, so MX goes and senders retry, a mail halt from M9, every open contract closed and new ones refused for sidecar subjects, shares included; no `rev/` entry; evs and gkm untouched, so data stays readable, writable, erasable and exportable; certificates kept unless the case orders revocation, so a lift restores service at once (owner decision 531) |

**Verification (owner decisions 41, 96).** Public names (§12.8, §13.9) and internet mail (§14.7) always need `network_verified`: a payment method (an in-window paid `transfer_balance` row, server/db_migrations.go:1653-1655) or the owner user's verified email or phone, the owner user being `network.admin_user_id`'s until M6 names a team's Owner (§7.5): a `network_user_auth_password` row with `verified` true, or a `network_user_auth_sso` row for Apple or Google, never a wallet, seed-phrase or guest row (server/db_migrations.go:2131-2156); api caches it like Pro (server/model/pro_model.go:164).

**Limits.** Beyond the states above and 21.5's breakers, §21 tightens a network's limits only through `network_sidecar_limit` rows citing its case, none for forwarding or sockets (§20.5; owner decision 66), and never `evs_closure_bytes_per_day` below its fixed 4 MiB floor: each eraser keeps its own allowance, so erasure stays possible at the storage limit, waiting at most as §11.13 and §15.7 state (§20.7; owner decision 146). The abuse worker opens a case, with no machine action, for a network whose closure bytes taken at the storage limit grow its stored bytes past it, that is, with closure bytes taken today, `network_quota_state.storage_over` set and the nightly count past the network's storage limit, one open case a network at a time (§20.7); review may tighten its erasers' allowances to the floor and its `config_statements_per_day`, which bounds the admissions, each a new eraser, that a day adds (§7.9's append limits, revocations exempt). Abuse of the team directory's access requests stays inside the network: §20.4's `directory_requests_*` and `directory_target_pending` limits and a directory admin's moderation (§16.11) handle it, since the server sees no request's content; §21 may tighten those limits the same way.

### 21.8 Intake, triage, appeals

**Intake** (D-ABUSE-5). `abuse@<root>`, `postmaster@<root>` (RFC 2142) and §14.8's reports to `<token>@rpt.bringyour.com` reach `rpt.bringyour.com`'s platform listener, SNI or not (D-SMTP-19, D-MAIL-10); a network's own `abuse@` reaches its admins (§15.8). Also: the form and a law-enforcement address on ur.io (21.11), feeds, Search Console, and registrar, registry and law-enforcement notices, which reach the rota two ways (owner decision 530): their senders' contacts name a company mailbox off the platform that the owner names (legal@ur.io, say), whose provider's rule fires the page, the rota then filing the case through the staff route (21.10); and mail to `abuse@` or `postmaster@` whose DKIM verifies under a domain `abuse.yml`'s `notice_senders` lists pages both rota members and opens a case of that domain's class, reading no body. The platform listener's role-mail intake hands api a role mail's recipient local part, its root and each DKIM signature's d= and verdict, never a body, through an internal route that takes a service token only, and api's `FileAbuseNoticeOfMail` matches them to `notice_senders` and opens the case; api and taskworker each install at start a retrying sink over the pager webhook in monitor's vault file, so a notice's page leaves the process that committed its case, keyed by the case, and taskworker's clock pass pages one a crash between the two left owed (owner decision 612). No mail or form text drives a kill, and the form offers no registrar or law-enforcement class. A trusted flagger's report carries `X-UR-Flagger-Key`, compared in constant time with the SHA-256 that vault's `abuse-flaggers.yml` keeps for each id `abuse.yml`'s `trusted_flaggers` lists; a match sets reporter class `trusted_flagger`, each flagger at most `flagger_kills_per_day` (20) kills a day, its later reports taking the ordinary row; each kill's review shows the flagger's id, and removing its line revokes it.

**Header-only parsing** (owner decision 78). Report and role mail get §14.8's parse and sealed copy or are dropped unread. Role mail the parse cannot attribute is answered at the end of DATA with `550 5.7.1 Not read. Report abuse at https://ur.io/abuse` and dropped unread, so the sender's own MTA returns the pointer to the person, with no auto-reply, backscatter or stored address (owner decision 533); attributed role mail keeps its 250 and sealed copy, and report-token mail is unchanged. The form takes URLs and header blocks.

**Pipeline.** Each report becomes an `abuse_case`, joined to a network by host or address (§12's label map; a burner address names its `<net>`), headers (§14.8) or edge `connection_id` (24 h); a report naming no URnetwork host, address or connection leaves no case, and the form answers the same either way, so it tells no one which names exist; third-party data is dropped after the join, except a reported URL's path and query, which the case keeps until its first review ends, at most its review clock, so that reviewers open the page reported (§13.9; owner decision 207); a reporter's address and free text are never kept, and of free text only an appeal's own reason is stored.

| Signal | Machine action | Review (v0: business hours, the action holding) |
|---|---|---|
| §14.8 high or medium join | §14.8's ladder | ≤24 h |
| Web Risk or feed hit; trusted-flagger report naming a URL | host kill | ≤24 h |
| Any registrar or registry notice about `<root>` or bringyour.com; a law-enforcement emergency notice, EU removal orders included | none; the rota kills a host a registrar's or registry's URL names within the same 1 h (owner decision 530) | pages both members of §19.8's rota at once, at any hour from M5 (owner decisions 134, 143); handled within 1 h: removal orders and registrar or registry notices by the rota, production orders and other data requests routed to counsel's out-of-hours contact (`config/<env>/abuse.yml`) |
| A report of phishing, malware or command-and-control naming a `<root>` URL, a customer's custom host included, or a report of CSAM or a threat to life | none | ≤4 business hours, every tier (owner decision 525) |
| Other | none | ≤4 business hours on probation; 72 h paid, 7 d Community |

```text
clocks    ≤24 h, 72 h and 7 d are elapsed hours, a deadline outside business hours moving to the next open;
          ≤4 business hours counts open hours only, so a kill at Friday's close is due at Monday's open, 63 h
          later; open hours run up to close, not through it, and a deadline exactly at close stays there;
          a paged notice's 1 h ignores the calendar
standing  "on probation" is the probation standing; restricted takes its tier's clock, and a tier or
          standing the abuse worker does not know takes 4 business hours
calendar  abuse.yml's business_hours (21.16): UTC by default, with no holidays; an open or close a clock
          change skips falls at the change's instant, one it repeats at its first pass, and hours wholly
          inside a skip do not exist that day
```

**Notice and appeal.** Owners and Admins get the category, target, case id and an appeal link unless a sealing order (18 U.S.C. §2705(b), §3123(d)) or a CSAM case bars it; a name sent to review names its case to the caller at once, in its refusal's `case_id`, before any reviewer acts (21.6; owner decision 581). A barred case shows the network its standing and nothing else: `GET /abuse/cases` omits it, `POST /abuse/appeal` answers as for an unknown case and `GET /abuse/status` shows the standing alone; when a sealing order lapses, the notice goes out with the case id and appeal link and the appeal window runs from it, and a CSAM case stays barred. Admins appeal within `abuse.yml`'s `appeal_window`, 6 months by default (DSA Art. 20's floor), a filed appeal reopening the case (21.10, 21.16, §14.8), and a second reviewer, never the action's own, decides with reasons (DSA Art. 17); reviewers never see sealed reports.

### 21.9 Legal process under end-to-end encryption

**Posture (owner decision 93).** Counsel reviews each order. Affected Owners and Admins hear of a request before production unless a sealing or nondisclosure order bars it (18 U.S.C. §2705(b)), and after it lapses. No prospective-collection capability is built, so pen register and trap-and-trace orders (§3123) reach only retained data. Through an EU addressee, production orders (Regulation 2023/1543, applied since 2026-08-18) need data within 10 days, 8 h in emergencies (https://www.reedsmith.com/articles/eu-e-evidence-new-service-provider-obligations-from-18-august-2026/), and their issuer informs the user (https://www.crossborderdataforum.org/analysis-eus-recently-adopted-e-evidence-regulation/), so counsel decides on URnetwork's own notice; terrorist-content removal orders need action within 1 h (Regulation 2021/784 Art. 3(3), https://eur-lex.europa.eu/eli/reg/2021/784/oj). Out of hours, 21.8's pager meets the 1 h with the kill switch and the 8 h through counsel's out-of-hours contact.

**Production** reaches only §2.8's rows while retained, never content, keys, internal names or paths (§2.5), notably:
- accounts and identities (api-1, api-5), the projection's reach graph (api-7) and abuse cases (api-14);
- connect-1's contract pairs (client ids, bytes, times), for the horizon connect-1 states;
- evs's push history (sidecar ids, times, path tokens, padded sizes; evs-4, evs-12, evs-14), kept for the repo's life by default, DROP statements included: who, when, which token paths and how many versions (evs-12); its drops', drop jobs' and dry runs' state for 30 days after each ends (evs-28) and its 7-day request log (evs-7); gkm's membership as sidecar ids;
- edge records for 24 h (tls-3, with keyed visitor-address hashes; mx-2, with no sender address) and, from M9, send records for 30 days (smtp-3).

It never reaches relay frames or dials (connect-2), inbound sender addresses (mx-2), client addresses (I-13) or DNS queries (dns-2). A compelled URnetwork could, from then on, log client, visitor and resolver addresses (connect-3, tls-2, dns-2) and use §2.8's EX1-EX8, notably EX3 outside Team strict mode (owner decisions 98, 135), but add no reader against customer signatures (§2.7).

**Preservation holds (owner decisions 133, 184).** A hold keeps one network's in-scope records existing at placement until its kind's deadline (§2703(f): 90 days, renewable once; §2258A: 1 year), and collects nothing new. TTL sweeps skip those rows; `copied_rows` copies what drops or is overwritten on its own: rows of partitions that drop whole (tls-3, smtp-3, mx-2), connect-1's `transfer_contract`, `contract_close` and `contract_close_report` rows naming a client of the network, copied at placement as compressed parts while connect-1's horizon reaper, its close-evidence horizon and its weekly partition drops wait only while a hold placed before their range's end has an unfinished copy, so no keep rule is added and every drop stays whole (owner decision 529), and the Redis soft state existing at placement (evs-8's lease fields, gkm-10's acks; owner decision 136). A network's or client's deletion (`RemoveNetwork`, `RemoveNetworkClient`) on a held network reads as done to the user and, in its own transaction, copies the in-scope rows it deletes (api-1, api-4, api-5, `network_acl_head`) into the hold's `copied_rows`, with no refusal, hint or admin event; the repo shreds it starts still run under owner decision 133, and the idle client reaper, a TTL sweep, skips held rows (owner decision 526). A hold does not reach evs-7's or ops-1's logs, which go at 7 d, though a production reaches them while they are retained (owner decision 529). api mirrors each hold as `hold/<network_id>/<case_id>/_` on the first metadata cluster (§11.8; owner decision 145), so §11.13's GC and §10.6's reconciler skip in-scope objects on every cluster, and evacuation moves a held network's batched records, a shredding repo's included, into packs and parcels that nothing deletes while the hold stands (evs-19). A drop of a path's history (§11.7) whose targets a hold covers still commits: it reads, lists and bills as finished, as an unheld drop would, and its dropped versions are served to no one, while its deletions wait until every covering hold has ended (§11.13); no answer, listing or bill tells the network that a hold exists, so a sealed order stays sealed (owner decision 184). A site loss voids what a hold kept on the file cluster, which has no off-site copy (owner decision 94); §19.10's restore returns its rows and tells counsel.

```text
abuse_legal_hold(network_id, case_id, part, kind, scope, place_time, report_time, renew_time, expire_time,
                 copied_rows, copy_state)
object   hold/<network_id>/<case_id>/_ is UTF-8 JSON of at most 1 KiB, unsigned, keys in this order:
         {"version":1,"network_id":"<id>","case_id":"<id>","kind":"preserve_2703f"|"report_2258a",
         "scope":"network"|["<repo_id>",...],"place_time_ms":<int>,"expire_time_ms":<int>}; a renewal rewrites
         it If-Match, keeping place_time_ms; a body that does not parse, or an unknown version, kind or scope,
         covers the whole network, and a record past expire_time_ms is no hold; renew_time set refuses a
         second renewal, and report_2258a's deadline runs from report_time
part     the primary key is (network_id, case_id, part): part 0 is the hold itself, and parts 1 and up each
         hold at most 16 MiB of compressed rows in copied_rows, so a busy network's tls-3 rows fit 21.16's
         seven tables
scope    "network", or a list of 1 to 16 repo ids, each covering that repo's objects on every cluster and its
         gkm group; server rows (tls-3, mx-2, smtp-3, connect-1's, api's) are covered at the network
         whatever the scope; counsel sets it from the order, "network" by default; scopes compare by
         containment (owner decision 527)
kind     preserve_2703f  90 d from placement, renewed once for 90 d by a renewed request (18 U.S.C. §2703(f)(2))
         report_2258a    1 year from the NCMEC report (18 U.S.C. §2258A(h)); not renewable here
overlap  a repo or row stays until the latest expire_time of any hold that covers it; expiry resumes TTL
         sweeps, GC, held shreds at §11.12's phase 5 and held drops' deletions (§11.13)
always   users' --now, the 7-day timer and per-entry erasure proceed under every kind, destroying keys; a hold
         keeps only the ciphertext they leave (owner decision 133; §11.12's phase 4); a drop, even with now, is
         not user-initiated shredding: a hold defers its deletions (owner decision 184)
counsel  before holds ship (M5), confirms each kind's applicability and owner decision 133's condition: that
         deleting wrapped keys to ciphertext URnetwork cannot read is permitted, beside which it sees the
         silent deferral of a held network's deletions (owner decision 526) and connect-1's rows in holds
         (owner decision 529); until it does, abuse.yml's holds_enabled, false, refuses placement, and
         readers of hold/ need no gate, since no object has no effect
```

**Copyright and child safety.** The edges are §512(a) conduits: host notices follow 21.4's ladder (§512(i)); evs notices go to the network. A §512(c)(2) agent is registered and renewed every 3 years (https://www.copyright.gov/dmca-directory/). On actual knowledge, CSAM goes to NCMEC, with no duty to scan (18 U.S.C. §2258A(a), (f)); a report places a `report_2258a` hold.

### 21.10 Retention and access

§2.8's list is the only TTL table (D-ABUSE-7): cases, actions and appeals stay 13 months after their case's last close, legal requests, productions and `abuse_access_log` 3 years, holds until their kind's deadline (21.9), `network_abuse_state` only while current. A case closes when each of its actions is lifted or upheld by review, or, with none, when it is reviewed; an appeal filed within `appeal_window` (21.8) reopens it, and it closes again at the appeal's decision.

**Staff.** The `abuse` role acts only through api's one staff route, `POST /abuse/action` (`x-internal`), whose kinds are lookup, by case id or join key and never in bulk, review, an appeal's decision, a limit row, a hold's placement and renewal, a legal request, a production's sign-off, a restore flag's clear, a mailed action's re-apply and a notice's filing, `file_notice`, by which the rota files a notice its company mailbox paged (21.8; owner decisions 530, 612). Each staff member holds a bearer of their own, kept in vault's `abuse-staff.yml` only as its SHA-256 with the member's reviewer id, roles (reviewer, legal, engineering) and an expiry at most 90 days out, compared in constant time; the lb refuses the route from outside the operators' addresses. Each read writes `abuse_access_log` before it answers, an appeal's reviewer differs from the action's, and a production needs one legal and one engineering id: `legal_request` keeps who signed, `legal_signoff_id` and `engineering_signoff_id`, each a staff member's opaque id from abuse-staff.yml as a reviewer id is, which api-14 names (owner decision 259). The staff client is `sidecarctl abuse <kind>`, one subcommand per kind, `sidecarctl abuse file_notice` among them (owner decision 612), reading the bearer from a file a flag or `UR_ABUSE_STAFF_BEARER_FILE` names, never from an argument, and printing the answer's JSON; there is no web UI (owner decision 532). "Separate from ops" is a process rule in v0, since nothing stops someone who holds vault or Postgres.

**Restore.** A Postgres restore returns §21's tables, `network_tls_suspension`, zone and host suspensions and halts to the sidecar dump's age (§19.10); it lifts no recorded action:

```text
record   each action (kill, zone or host suspension, halt, §21 suspension, limit tightening) and each lift,
         a lift being an action of its own, kind lift, whose target is the lifted action's id, goes to the
         abuse mailbox (config/<env>/abuse.yml) as {action_id, case_id, category, network_id, kind, target,
         until, time, mac}, kept as api-14's actions; each hold placed, renewed or ended goes to the
         legal-request mailbox as {event, case_id, network_id, kind, scope, place_time, expire_time, mac},
         kept until its expire_time; api or taskworker sends each straight after its commit through their
         SES path, setting mailed_time, and the abuse worker retries each minute a row without it; both
         mailboxes sit at one provider outside URnetwork's Postgres and clusters, which the owner names, so
         it and SES see only each record's sender, time and size (owner decision 208)
mac      HMAC-SHA-256 over the record's other fields as canonical JSON, under abuse_mailbox_mac_key; a seal
         alone stops no forgery, since anyone can seal to its public key
seal     HPKE-XWing as smtpedge's sealed report copies (KEM 0x647a, HKDF-SHA256, AES-128-GCM, base mode),
         info "UR abuse 1.0 record", body u8(1) || enc (1,120 B) || ct, the plaintext the record's canonical
         JSON, mac included; mailed as a text/plain body of the body's base64 (owner decision 535)
keys     vault's abuse-mailbox.yml, mounted on api and taskworker alone, holds abuse_mailbox_mac_key (32
         random bytes) and abuse_mailbox_seal_public_key (1,216 B), both base64; the private key is the
         32-byte X-Wing seed (draft-connolly-cfrg-xwing), kept offline beside §19.10's runbook and reachable
         by no running service; sidecarctl abuse mailbox-keygen -out <abuse-mailbox.yml> -private-out <file>
         draws the pair and the MAC key and writes the vault file and, apart, the seed as
         abuse_mailbox_seal_private_key, both 0600, printing neither; a rotation runs it again, and the
         runbook keeps every old seed until its last record's ttl ends (owner decision 535)
restore  §19.10's abuse step, after the dumps load and before the token exchange reopens, the edges read
         the restored rows or §12.6's restore step builds the zone: the abuse role (§19.8's rota, at any
         hour) re-applies, in mail order and idempotently by action_id, every unexpired action and every
         lift mailed after the dump, each opened with the offline seed and its mac checked, re-creating its
         case under its id; a record whose mac fails or is missing is refused and printed, and the step
         prints its plan, applying it only on an explicit apply
check    §12.6's step flags restored RRsets of networks with open cases; the abuse role clears each flag
gap      an action committed in the seconds before the primary's loss, its mail not yet sent, is lost
         with it; tlsedge still keeps a kill that Redis holds (§13.9), and feed and Web Risk hits recur
```

### 21.11 Transparency

A semiannual report counts requests by instrument and country, accounts affected, productions, holds, sealing orders, DMCA notices, abuse actions, appeals, NCMEC reports and root incidents. ur.io publishes the signed, dated quarterly canary (sidecar/design/pitch5.html:933) and the report template with "end-to-end encrypted" (owner decision 119; §23.8), and from M5, with `rpt.bringyour.com`, the RFC 3207 deviation that §15.4's 530 links (owner decision 33). Its paths are `/abuse` (the form), `/legal/law-enforcement`, `/legal/rfc3207-deviation`, `/legal/transparency` and `/legal/canary`.

### 21.12 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| A URnetwork warning page on user names; parsing report bodies | clearer to visitors; richer evidence | edge termination under a URnetwork key (PLAN.md:84), blinding the CT watch; user mail in URnetwork memory | ruled out (owner directive) |
| Content scanning in the sidecar | catches CSAM and phishing | breaks "private from us"; server-steered lists | rejected |

### 21.13 Decisions proposed

**D-ABUSE-1 (proposed).** Controls act only on names, metadata, rates and reports (21.4). *Why:* the directive; modified sidecars skip sidecar-side controls.

**D-ABUSE-2 (proposed).** 21.5's breakers guard `<root>` and the shared addresses, with thresholds in pro.yml `sidecar_abuse:`. *Why:* reputation is shared (owner decision 124), and per-network rates stay below Gmail's feedback thresholds ([R:ext-email-zk] §2.8, §2.9).

**D-ABUSE-3 (proposed).** Takedown follows 21.6 and 21.8, within 1 h for public phishing or malware 21.8's signals confirm, and, by the rota, for paged removal orders and registrar or registry notices, no mail or form text driving a kill (owner decision 530); `<root>` is verified in Search Console. *Why:* a registrar suspension, required for phishing since 2024-04-05, takes "all third-level domains" (https://www.icann.org/en/contracted-parties/advisories/documents/advisory-compliance-with-dns-abuse-obligations-in-the-registrar-accreditation-agreement-and-the-registry-agreement-05-02-2024-en), so every registrar or registry notice pages; passthrough leaves only connection refusal.

**D-ABUSE-4 (proposed).** Screening, standing and verification follow 21.6 and 21.7. *Why:* these are a brand's only ways in; Sybil networks are cheap.

**D-ABUSE-5 (proposed).** Intake and appeals follow 21.8, report mail never touching the SNI router: role mail no report attributes is refused unread with a pointer to the form (owner decision 533), and notices reach the rota through a company mailbox off the platform and `notice_senders`' verified role mail (owner decision 530). *Why:* reporters without SNI must deliver; the directive; AUTHZ1; DSA Art. 17; a refusal reaches the person through their own MTA with no backscatter or stored address.

**D-ABUSE-6 (proposed).** Legal process and holds follow 21.9 (owner decisions 93, 133), each hold with its statutory kind and deadline. *Why:* a request reaches only what retention keeps; a hold revives no shredded key; one generic hold cannot carry §2258A's 1-year preservation.

**D-ABUSE-7 (proposed).** Retention, access, restore and transparency follow §2.8, 21.10 and 21.11, each mailed record MACed under a vault key inside a seal to an offline key (owner decision 535). *Why:* D-TRUST-7; expired keys protect users even from a compelled URnetwork; a dump-age restore must lift no action, and re-apply no forged lift, which a seal alone cannot stop.

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
- **API routes** (api, §19.4): `POST /abuse/report` (Public; 30 reports an hour per caller, each URL and each header block a report, so a request of n counts n and is refused whole, nothing taken, when one would pass the limit (owner decision 582), keyed by the address's peppered /29 or /56 hash and counted in Redis, so the limit holds across api processes, under `AbuseRouteSettings`' window and count, a refused report counting too and the lb's excluded infrastructure addresses counting nothing (§2.8 api-14; owner decision 536); a trusted flagger's `X-UR-Flagger-Key`, 21.8); `GET /abuse/cases` (Network, read roles; never a barred case, 21.8); `POST /abuse/appeal` (Owner or Admin; never a client token); `GET /abuse/status` (Client, own state; sidecar-classified, on §7.4's `strict_exp` allowlist); `POST /abuse/action` (21.10's staff route, off the public API: a staff bearer, never a client token; it refuses a `network_sidecar_limit` row that sets `evs_closure_bytes_floor` or `evs_closure_uploads_per_s`, both fixed, or takes `evs_closure_bytes_per_day` below the floor: §20.5, §20.7); and an internal route the platform listener's role-mail intake calls, a service token only, never a client token, with a notice's recipient local part, its root and each DKIM signature's d= and verdict, never a body, which files it through `FileAbuseNoticeOfMail` (21.8; owner decision 612).
- **Tables** (api; migrations ≥926 in §19.7's MG5): `abuse_case`, `abuse_action`, `abuse_appeal`, `network_abuse_state`, `abuse_legal_hold` (with `kind`, 21.9), `abuse_access_log`, `legal_request`.
- **Services and config:** the taskworker abuse worker (feeds, Web Risk, the CT watch, breakers, 21.7's closure-growth cases, TTL sweeps, hold copies, record mail retries, the notice clock pass); the breakers' sources, which taskworker installs at start with `smtpedge.yml`'s sending addresses: a Postmaster Tools client for `<root>`'s daily statistics, an SNDS client for the addresses' file and a local match of those addresses against the feed mirror's second copy on taskworker's host (21.5; owner decision 611); the notice pager, a retrying sink over the webhook in monitor's vault file `monitor.yml`, which api and taskworker each install at start, two more readers of the pager's credential (21.8; owner decision 612); pro.yml `sidecar_abuse:` thresholds; vault's `abuse-staff.yml` (21.10), `abuse-flaggers.yml` (21.8), `abuse-mailbox.yml` (21.10), a Web Risk key, and `abuse-postmaster-tools.yml` (a service account's refresh credential) and `abuse-snds.yml` (SNDS's key), external items the owner provides (§23.7; owner decision 611); and `config/<env>/abuse.yml`, which holds no secret:

```text
abuse.yml keys
abuse_mailbox,          where 21.10's records go, at the provider the owner names
  legal_request_mailbox
notice_senders          domain -> class: role mail whose DKIM verifies under a listed domain pages both rota
                        members and opens a case of that class, reading no body (21.8)
trusted_flaggers        [{id}], each id's key hash in vault's abuse-flaggers.yml; flagger_kills_per_day: 20
protected_names         {roots: [...], platform: [...]}, read into AbusePolicySettings' RootNames and
                        PlatformNames: a target equal to a root, or equal to or under a platform name, is
                        refused, and empty lists refuse every target (21.4); §12.5's reserved check also reads
                        the first label under a root
appeal_window           6 months, DSA Art. 20's floor (21.8, 21.10)
business_hours          {zone: UTC, days: [mon, tue, wed, thu, fri], open: "09:00", close: "18:00",
                        holidays: []}; mode is business or always, always being M6's 24/7; a missing or unknown
                        mode, an empty or local zone and hours past midnight are refused; main's zone is set
                        with the rota's staffing
holds_enabled           false, refusing placement until counsel confirms (21.9; §23.7)
feeds                   URL feeds, each a plain-text list of URLs or hosts, at most 64 MiB a fetch (21.6)
also                    Web Risk, reviewer and pager routing, and counsel's out-of-hours contact (21.8)
```
- **Assumptions about other sections:** §14 and §15 run `rpt.bringyour.com` from M5, §15.4's platform listener refusing role mail no report attributes (owner decision 533); §8.6's `hardDeny` reads a §21 suspension as server state that never reaches evs (owner decision 531); §12.8 answers a name sent to review with `screen_review` (owner decision 534); §19.4 mounts the abuse vault files and the lb refuses `POST /abuse/action` from outside the operators' addresses (owner decision 532); §19.8's out-of-hours rota carries 21.8's notices from M5, paging both members at once, and review runs 24/7 from M6; §19.10 restores holds' rows, re-places later holds, tells counsel and runs 21.10's abuse step in 21.10's order, checking each record's mac, and §12.6's restore step flags restored RRsets of networks with open cases; §2.8's header and api-14 publish `copied_rows` (tls-3's, smtp-3's and mx-2's rows, connect-1's contract rows, the rows a held network's deletions remove, evs-8's lease fields, gkm-10's acks), and connect-1's, mx-2's, evs-8's and gkm-10's ttls except a hold's copy; api-14 lists both mailboxes' sealed copies (21.10) and the report limit's attempt histories; §11.13 moves a held shredding repo's batched records, and §11.12 resumes its shred at phase 5 when the hold ends; §11.13's drop job rereads `hold/` before each batch of deletions and defers a covered drop's deletions until every covering hold ends, the drop reading, listing and billing as an unheld one (owner decision 184); §16.11's daemons and readers apply the directory's request limits as `GET /sidecar/limits` gives them, §21's rows included (§20.4); §23.7 tracks counsel's confirmation of owner decision 133's condition and of each hold kind's applicability (`preserve_2703f`, `report_2258a`), with what counsel reads beside them (owner decisions 525, 526, 528, 529), `holds_enabled` refusing placement until then; §22 tests sweeps, access logs, holds beside shredding, a held --now shred's batched records packed, kept until the hold ends, then deleted (FS-6), hold kinds' deadlines (FS-48), clocks across a weekend (FS-49), held drops (FS-92) and, at M5, FS-39's report-intake cases and S7's SNI-less `abuse@<root>`.

### 21.17 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Safe Browsing flag (statichost.eu, 2025-09-25: https://www.statichost.eu/blog/google-safe-browsing/) or registrar hold on the root | Medium | Critical | 1 h kills, Web Risk, Search Console, the pager, a user-only root (owner decision 13), the PSL later |
| Off-hours, a wrong kill holds until business hours, about 63 h over a weekend, and unpaged signals wait, a Search Console flag and a stranger's report of CSAM or a threat to life included (owner decisions 134, 525) | Medium | High | 21.8's signals only; appeals; counsel asked whether the weekend gap is acceptable (§23.7); 24/7 in v1 |
| Counsel rejects owner decision 133's condition or a hold kind | Low | High | asked before holds ship (M5) |
| A drop used to destroy evidence before a hold arrives | Low | Medium | the 7-day window keeps every byte for a hold to cover (owner decision 183); `now` drops stay visible in push history (evs-12); held drops delete nothing (owner decision 184) |
| False reports | Medium | Medium | reporter classes, host-level first, appeals |
| Free Sybil networks | High | High | probation, verification, the send gate, creation limits, label-scoped halts |
| A shared lb address is listed for a user name's phishing (§13.16), as for mail (§14.15's row), also blocking api and connect ingress there (accepted; owner decision 124) | Medium | High | §14.15's row; 1 h kills |
| Without a policy, untagged sidecars and their agents reach providers' LAN and loopback (accepted, disclosed; owner decisions 50, 120) | High | High | §2.18's disclosure; policies on any tier (owner decision 73); suspension |

### 21.18 Phasing

- **v0 (M5), before any public name:** 21.6-21.10 with `rpt.bringyour.com` and 21.11's RFC 3207 deviation, less the later items below; the DMCA agent; Search Console and registrar contacts; business-hours review, with 21.8's notices on §19.8's rota (owner decisions 134, 143); [holds once counsel confirms](DESIGN-DEFER.md#abuse-preservation-holds), `holds_enabled` refusing them until then (21.9). **v1 (M6):** 24/7 review; tightening the team directory's request limits (21.7).
- **M7:** reporters in the census (D-MAIL-9). **M8:** trusted flaggers. **M9** (owner decisions 35, 124): §14.8's ladder, the send gate and 21.5's breakers. **M10** (v1's format 2, owner decision 169): holds defer drops' deletions (§11.13).
- **Deferred:** DESIGN-DEFER.md holds an entry for the holds' switch and for [this section's v1 set](DESIGN-DEFER.md#abuse-v1) (owner decision 587).
- **With "end-to-end encrypted" (§23.8):** 21.11's trust documents; the first report six months after the first public name.
- **Blocking:** M5's names wait on intake, the report host, the kill switch and the pager; holds on counsel; M5's exit on FS-39's report-intake cases, FS-48, FS-49 and S7's SNI-less `abuse@<root>` (§22.7, §22.8); M9's sending on the breakers.
