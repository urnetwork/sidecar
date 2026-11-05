# Product requirements for the sidecar infrastructure: fact sheet

Research input for the design writers, 2026-11-03. Topic: what recURd and the consumer Burner product require of the sidecar infrastructure, traced to sources. Nothing described here is built.

Citations are `repo/path:LINE`, relative to `/Users/brien/urnetwork`. Short names: `PLAN` = `sidecar/PLAN.md`; `R` = `sidecar/mocks/recurd-app.html`; `M` = `sidecar/mocks/urnetwork-mobile.html`; `T` = `sidecar/mocks/team-management.html`; `UI` = `cli/UI.md`; `P5` = `sidecar/pitch5.html`; `FB` = `sidecar/FEEDBACK-SYSTEM.md`; `M2` = `sidecar/market2.md`; `TS` = `sidecar/reports/Tailscale tailnet onboarding and access.md`; `REC` = `sidecar/reports/Agent work record gaps and features.md`; `EXT` = `connect/EXTENDERUPDATE.md`. Line numbers in the HTML files are source lines. "inference:" marks my reasoning. Where a design note and the code disagree, the code wins, and the text says so.

## 1. Summary

1. PLAN covers the substrate: encrypted storage, sockets, names, mail and reach (PLAN:41-119). It does not cover the record semantics that pitch5 sells: a signed ledger, approval receipts, reach receipts, per-run coverage, two key domains and retention (P5:476-481, P5:892-904; M2:705-723).
2. Three PLAN choices conflict with the promises as written. Paths are unencrypted (PLAN:59). Access rules are stored on the server (PLAN:119). The TLS edge terminates TLS itself (PLAN:84). The promises say "private from us" (P5:579), a policy "compiled under your key authority… never reads it" (T:814), and "The certificate key stays in the sidecar" (P5:699).
3. Burner email exists only in the phone mock and `cli/UI.md`, and they use two different address schemes: `swift-otter-4821@burner.ur` (M:918) and `<alias>@<user>.ur.network` (UI:69). `.ur` is not a TLD. Aliases under a user's zone are linkable to each other, and network names can be reclaimed 24 h after a rename (`server/controller/account_controller.go:13`).
4. Nothing receives mail while the user's device is offline. PLAN has only a local SMTP server on the device and an outgoing SMTP edge (PLAN:87-104).
5. Pricing disagrees across sources: Team at $100/month flat (PLAN:350) against $20–40 a seat (P5:845); storage at 1/20/200 GB (PLAN:355) against 1/100 GB (UI:87-89); daily email at 5/200/20000 (PLAN:356) against replies only and 2000 (UI:76-78). The server has only `free` and `pro` tiers (`server/model/pro.go:74-75`).
6. The free tier caps a network at 2 connected top-level clients, and that cap has been enforced since 2026-11-03 (`config/all/pro.yml:54-57,87`). That conflicts with "any number of agents" on Solo (P5:844) unless the sidecar multiplexes agents onto one client or is exempted.
7. Team management is almost entirely new. A network has a single `admin_user_id` (`server/db_migrations.go:351-358`). Network-create SSO accepts only Apple and Google (`server/model/network_model.go:227`). API keys have no scope or expiry (`server/db_migrations.go:2872-2881`). The console mock assumes OIDC, SCIM, 7 roles, approval gates, auth keys, OAuth clients, HuJSON grants and signed membership (T:384-1124).
8. Names and certificates collide with reputation work. `ur.network` is not on the Public Suffix List. inference: every network therefore shares one Let's Encrypt limit of 50 certificates per 7 days. CT logs publish every publicly trusted name. EXT:160-166 keeps enterprise relays off `ur.network`, but the mocks put agent identities on `@brien.ur.network` (R:1222).
9. The "post-quantum" spine is narrower than the claim. connect prefers X25519MLKEM768 but falls back to X25519 (`connect/transfer_encrypt.go:377-385`), and MLS PQ ciphersuites are still an Internet-Draft.
10. The owner's open §13.1 decision gates feedback hosting, naming and signed membership (EXT:272-277; `factury/HANDOFF-1102-5.md:42-47`): either dedicated `recurd.dev` infrastructure, or URnetwork's network for worldwide reach only.

## 2. Facts with citations

### 2.1 What PLAN.md commits to

- Code and runtime: sidecar depends on connect, and server and sdk import it (PLAN:5-7). Service code sits in the module root (PLAN:13). The `Sidecar` struct holds "an authenticated jwt, connect client, api, and encryption key" (PLAN:14). The CLI speaks stdio MCP (PLAN:17-20). The sidecar runs in apps through `sdk/sidecar.go` and in the extension as a web worker (PLAN:28). Naming: "A network has a dns zone <me>.ur.network" (PLAN:25).
- evs: MLS (PLAN:44); one git repo per directory, keyed "in GKM" (PLAN:53); subscribe (PLAN:55); git over https (PLAN:57); client-id git identity and unencrypted paths (PLAN:59); minio (PLAN:61); checkpoints and a head read (PLAN:63).
- Other services: a fair scheduler picks one listener (PLAN:69); access control (PLAN:74); DNS/TLS edge (PLAN:80-84); outgoing-only SMTP edge (PLAN:89-97); local email (PLAN:104); MCP ingest (PLAN:109); bridge rules "stored on the server" (PLAN:115-119).

### 2.2 Requirements catalog

Product column: R = recURd, B = burner email, A = apps, All. Service column: evs; sock (abstract sockets); acl; edge (DNS/TLS); smtp; mail (local email); mcp; bridge; team (team management, PLAN:5 and PLAN:363 only); — means not in PLAN.md.

| ID | Requirement | Prod | Source | Service |
|---|---|---|---|---|
| N1 | Every agent, group, loop, TLS name and mailbox lives under the network zone `<me>.ur.network` | All | PLAN:25; R:1221-1222; UI:105 | edge |
| N2 | An agent gets `<agent>@<me>.ur.network` "when it registers", unique per network. On a conflict, one instance keeps the name, the other is renamed (`api-refactor-ci@…`), and "Reach grants tied to the old address are revoked" | R | R:918-924, 948-971, 1901 | — |
| N3 | One message to a group or loop address "fans out to every member"; membership is editable | R | R:1584, 1805; UI:25-27 | mail (partial). sock picks one listener (PLAN:69), so fan-out is — |
| N4 | Network directory of agents, groups and loops: "Any user or agent can inspect it" | R | R:1854 | — |
| N5 | Default admin address plus unlimited aliases, each an id or a group | B,A | UI:21-23, 68-69 | mail |
| N6 | Random burners on a shared domain, `adjective-noun-NNNN@burner.ur`, with a regenerate control | B | M:636, M:918 | — |
| N7 | Team custom domains: a TXT challenge `_urnetwork-challenge.<domain>`, plus aliases "for sign-in and addressing" | R | T:562-629; PLAN:364; M2:553 | edge, smtp (pricing line only) |
| N8 | A per-agent private address (`api-refactor-a7f3.recurd.dev`, `100.64.0.3`) | R | R:1103, 1372 | bridge; private DNS — |
| S1 | Session vault: every session from every harness under the developer's keys, owner-set retention, search on the developer's machine, secrets redacted before saving | R | P5:617-618; M2:790 | evs, mcp |
| S2 | Change set and restore for every tool path (shell, subagents, reverts); restore is previewed, stays inside the run's changes, and is recorded | R | P5:621-622; REC:276 | evs; filesystem watcher — |
| S3 | Team ledger of signed, hash-chained entries (`claim`, `change`, `handoff`, `ask`/`answer`, `approval`, `route`, `publish`, `context`, `check`, `membership`/`key`) carrying a trust flag and salted pointers | R | M2:705-723 | — (evs stores bytes only) |
| S4 | Two key domains: raw content under the developer's keys, actions and approvals under team keys. Every admin read becomes an entry the author can see | R | M2:482-486, 755-761; P5:640 | evs/MLS, not stated |
| S5 | Real-time sync: live activity on the web and the phone, and harness re-sync on save | R | P5:803; R:1006; M:721 | evs (PLAN:55) |
| S6 | Per-agent branch namespaces, explicit merges, compare-and-swap on shared refs, plain-git clone and export, and a published "twenty agents" load test | R | M2:513-531; P5:662 | evs |
| S7 | Retention: the ledger keeps ≥12 months, 90 days searchable; archive instead of delete; legal hold later | R | M2:466, 753; P5:903 | — |
| S8 | Erasure with the chain intact: per-entry keys and 256-bit salts, "from the first release" | R | REC:217-223 | — |
| S9 | Verifiable log (Tessera, C2SP, witnesses) and client packets (per-client keys, SD-JWT) | R | M2:796-797; P5:898 | — |
| S10 | Exports: JSON, and SIEM over an encrypted webhook (Splunk, Datadog), OTel GenAI, SCITT/COSE, in-toto | R | T:1027-1029, 1103; M2:799 | — |
| S11 | Read the head of one file without a clone, for the phone and web clients | A | PLAN:63 | evs |
| S12 | Storage quotas, counted against the transfer balance | All | PLAN:353-355; UI:87-89, 97 | evs |
| E1 | Each identity holds a title, password, one-time auth, URL and notes; a new entry "creates a new email+password" | B | UI:72-73; M:594-605, 633-657 | evs |
| E2 | Register with the OS as a password manager and autofill | B,A | M:465, 657, 808; `sidecar/mocks/index.html:102` | — |
| E3 | Incoming mail is stored encrypted ("encrypted on arrival") | B,R | PLAN:104; UI:80; P5:708 | mail |
| E4 | Reply from the alias, and compose new mail | B | M:584 | smtp |
| E5 | Daily send caps by tier; an abuse report against a message ID halts the network's sending for a day; DMARC and abuse reports tie back to the sending network | All | PLAN:89-97, 356; UI:76-78 | smtp |
| E6 | Accept mail while the device is offline | B | PLAN:104; UI:67 | — |
| E7 | Outside mail is untrusted; the first message to a new recipient waits for approval; untrusted mail cuts off send, forward and publish | R | P5:707, 736; M2:504-505 | — |
| E8 | Approval by email reply, from DKIM-verified team members | R | P5:899; M2:603 | mail; DKIM check — |
| E9 | The per-send record lists every recipient, including BCC | R | M2:457, 478 | — |
| E10 | Chat with an agent from the web and the phone, a broadcast "global mic", and agent-to-agent mail | R,A | R:738-744, 1304; M:739-745 | mail (partial); delivery into the harness — (mcp only ingests) |
| X1 | A forward is a grant: "One agent, one port, one time window, approved by a person", encrypted between sidecars | R | P5:677-683; R:1563 | bridge, acl |
| X2 | Private IPs plus routed subnets, Linux and WSL2 first | R | P5:686-692, 894 | bridge |
| X3 | Egress only "through exits you run", never member egress | R | P5:689; `sidecar/gap.md:286`; M2:547; R:1105 | — (UI:117 "client egress spec") |
| X4 | Model access per agent and per model; each request signed with weight digest, quantization and engine; routes `claude-*`→anthropic, `llama-*`→vLLM, `*`→ask | R | P5:774-781; R:1751-1756 | bridge forward only; L7 routing and receipts — |
| X5 | The sidecar installs inside cloud-agent environments | R | M2:537; P5:678, 717 | — |
| X6 | Public TLS name: "Explicit, authenticated by default, and short-lived"; agent control panels refused; passthrough; certificates issued automatically | R,All | P5:695-701; M2:495, 506; PLAN:80-84; UI:105-122 | edge, sock |
| X7 | Reach receipts: owner, approver, scope, duration, and who connected | R | M2:798; P5:898 | — |
| X8 | "One switch revokes an agent's forwards, addresses, names, and mail" | R | P5:729 | acl (partial) |
| X9 | Invite an external network to forward in, and accept invites | All | UI:50-51 | bridge |
| X10 | Enterprise posture: dedicated `recurd.dev` names and IPs, publicly trusted leaf, published allowlist, every receipt names its relay, no camouflage | R | EXT:160-181, 191-195, 237-251 | — (§13.1) |
| T1 | OIDC SSO (Okta, Google Workspace, Entra, custom ES256/RSA) and SCIM. SCIM syncs membership only and maps groups to `group:x@domain` | R | T:384-468 | team |
| T2 | Seven roles: Owner, Admin, Member, Network admin, IT admin, Billing admin, Auditor | R | T:1118-1124 | team |
| T3 | User and device approval; pre-approved keys skip it | R | T:477-544, 779-799 | team |
| T4 | Auth keys (reusable, ephemeral, pre-approved, tagged; 7/30/90 days); OAuth clients that mint short-lived tag-bound keys (`devices:core`, `auth_keys`, `all`); one-command, QR and MDM join | R | T:648-771 | team |
| T5 | One deny-by-default HuJSON policy (`tagOwners`, groups, autogroups, client-attested postures, tests), "compiled under your key authority and enforced on every client" | R | T:813-929 | acl, but PLAN:119 stores rules on the server |
| T6 | Default grant: `tag:recurd` → `autogroup:self` on tcp:443 | R | T:862-867 | acl |
| T7 | Signed membership: a quorum of customer signing nodes (2-of-3; Secure Enclave, YubiHSM, offline), always on, trust on first use | R | T:939-1012 | — |
| T8 | An audit log "end-to-end encrypted to your team and hash-chained", with export and SIEM streaming | R | T:1021-1029, 1103 | — |
| T9 | Several teams per user ("Team plan", "Sandbox") | R | T:288-292 | team |
| T10 | Agent tokens of at most an hour, bound to the sidecar's key, never in the agent's environment; a sponsor for every agent, killable from Agent 365 or Okta | R | FB:139; M2:425-443 | — |
| H1 | MCP over stdio. Capture from MCP traffic, hooks, telemetry and filesystem/git, with a per-run entry stating what the record could not see | R | PLAN:17-20; M2:535, 745-751; P5:941 | mcp (ingest only) |
| H2 | Instruction-file writer with a truncation warning; config edits go to review; secret scan on shared writes; no long-lived secrets | R | P5:629-631, 737-738; M2:507-509 | — |
| H3 | A global harness config with per-agent overrides; agents re-sync on save | R | R:986-1009, 1728-1760 | evs |
| H4 | Claims and leases, and handoffs, across harnesses | R | P5:625-636; M2:714-716 | evs |
| H5 | Approval receipts: one action ID, permission mode, revocable grants, SSH signature for high-risk steps | R | P5:727; M2:792 | — |
| H6 | Run inventory, per-run cost and tokens, stats, and a backtest ("Re-run the last 20 tasks") | R | M2:793, 800; R:1601-1640; M:716-718 | — |
| A1 | Phone tabs: Burner, recURd (agents, cost, live activity, messages) and a Feedback chat | A | M:414-416 | several |
| A2 | Web quick tools on ur.io (quick burner, feedback), log-in required, running a `DeviceRemote` in the browser | A | UI:159-165 | — |
| A3 | recurd.dev "Log in with URnetwork… No password" | R | R:712-714 | — |
| A4 | `ur daemon`, `install-daemon`, and `--instance` storage scoping | All | UI:10-19 | cli |
| A5 | An open-source client, relay and entry format with reproducible builds; self-host any part, air-gapped if needed | R | P5:576, 811, 930 | — |
| F1 | Feedback: ids, a network log, status pushback, a closed-schema auto tier, sealed bodies, a team copy and a subscribe stream | R,A | FB:63-121, 146-191, 234-252 | — |
| Z1 | Trust documents (audit, threat model with a metadata list, DPA, canary, "no token" statement) ship before "end-to-end encrypted" is used publicly | R | P5:927-934 | — |

### 2.3 The burner email product, as the mocks and notes define it

- **Address formats.**
  - Shared random: `swift-otter-4821@burner.ur`. The generator builds adjective-noun-(1000–9998)`@burner.ur` (M:918), and the create sheet regenerates it (M:636).
  - `cli/UI.md` puts the burner on the user's own zone instead: an admin address `admin@<user>.ur.network` (UI:68), and "as many `<alias>@<user>.ur.network` as they want, either as an id or a group" (UI:69).
  - The same file also says "you@ur.network is the default admin email, refer to with name "@"" (UI:21), and `ur id create <name> # name@you.ur.network` (UI:23). It contradicts itself.
  - Agent mailboxes use the same zone: `api-refactor@brien.ur.network` (M:712).
  - `.ur` is not a TLD: it is absent from IANA list version 2026110300 (https://data.iana.org/TLD/tlds-alpha-by-domain.txt). inference: `@burner.ur` is a placeholder, and the real shared domain is undecided.
- **Per-alias features.**
  - Shown for each alias: "Used at shopify.com, reddit.com", unread badges, a label ("Banking alias"), the counts "4 logins 2 notes", and a creation date (M:467-468, 541-558).
  - The detail screen shows "Active · created Oct 12 · forwards to you", "Reply from this" and Compose (M:583-584), an inbox (M:587-591), saved logins with reveal and copy (M:594-599), and notes such as "Recovery codes — Shopify 8 codes" and a shipping alias with a street address (M:602-605).
  - The create sheet has a generated address, an optional website and username, a generated password ("Strong · 14 characters") and an optional note. It ends "URnetwork will autofill this login on shopify.com next time." (M:633-657)
  - `cli/UI.md` adds "one time auth" (TOTP) to every id or group (UI:72). The mock shows no TOTP field.
- **Password manager.** Users are told "Set URnetwork as your password manager — autofill logins everywhere." (M:465, 808). The mockup index admits "The autofill/OS-integration story… is implied, not specified" (`sidecar/mocks/index.html:102`). The platform hooks are an iOS credential provider extension, which also handles one-time codes (https://developer.apple.com/documentation/authenticationservices/providing-one-time-passcodes-to-autofill), and an Android `AutofillService` on API 26+ (https://developer.android.com/identity/autofill/autofill-services).
- **Send, reply and quotas.**
  - `cli/UI.md`: "only replies if free", "2000/day if pro" (UI:76-78).
  - PLAN: Community 5, Pro 200, Team 20000 a day (PLAN:356), and "N for free is small" (PLAN:89).
  - Abuse: "Abuse reports against the message id halt sending for a day from that network." (PLAN:91)
  - The mock shows Compose with no tier gating (M:584).
- **Storage.** "All messages are stored in encrypted storage" (UI:80), and PLAN:104 agrees. Storage is unlocked by a pass-encoded keychain ("changing pass rencodes the keychain", UI:82-85), which is a different key model from PLAN's MLS/GKM (PLAN:44-53).
- **When the device is offline.** PLAN's mail server "runs locally and terminates a public mail.<me>.ur.network" (PLAN:104). The only hint is UI:67, "[if remote is not connected, start a local device that listens]". No source names a queue.
  - SMTP senders retry at intervals of "at least 30 minutes" and give up after "at least 4-5 days" (RFC 5321 §4.5.4.1, https://www.rfc-editor.org/rfc/rfc5321.html).
  - inference: one-time-code mail will expire before a retry lands.
  - Phones and extensions make poor listeners. A Chrome MV3 service worker stops "After 30 seconds of inactivity" (https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle).
- **Linkability and privacy.**
  - inference: addresses under `<user>.ur.network` reveal the network name and link every alias to every other one; only a shared domain gives unlinkability.
  - The SMTP edge is designed to bind each send to its network for abuse handling (PLAN:90-97). So URnetwork can link burner sends to an account.
  - "Used at" site lists (M:467) are sensitive. inference: they must be stored under user keys.
  - "forwards to you" (M:583) may mean forwarding to an outside mailbox. inference: that would need SRS/ARC handling; open question Q2.
  - Network names are reclaimable 24 h after a rename (`server/controller/account_controller.go:13,159-171`). inference: a new owner of `brien` would receive `*@brien.ur.network` mail, including password resets for every site the burner was used at.

### 2.4 recURd's infrastructure needs, and what PLAN.md lacks

- **Covered by PLAN:** storage and sync for the vault, change sets and handoffs (PLAN:53-63); forwards and IPs (PLAN:115-119); public names (PLAN:80-84); agent mail (PLAN:104). REC:294 maps the original seven features the same way.
- **Not in PLAN** (rows marked "—" in §2.2):
  - absent: N2, N4, N6, S3, S7-S10, E2, E6, E7, E9, X3, X5, X7, X10, H2, H5, H6, T7, T8, T10, A2, A3, A5, F1, Z1;
  - partly covered: N3, N8, S2, S4, E8, E10, X4, X8, H1.
- **Approval receipts lose their carrier.** M2:593 put approval receipts "on the URmessage base". That repo is being deleted, so the carrier must be built in sidecar.
- **Feedback system dependencies** (FB):
  - client-side sealing with X25519MLKEM768 (FB:236);
  - a team copy written into the vault or ledger "under the developer's keys" (FB:121);
  - agent tokens minted by the sidecar, ≤1 h and bound to its key (FB:139);
  - a `feedback.auto` grant, possibly in the access policy (FB:140, [G3]);
  - a team `feedback.egress` policy (FB:141);
  - a subscribe stream on "a connection the sidecar opens" (FB:306, [G2]);
  - admin webhooks (FB:319);
  - push and mail notifications without content, on a separate sending identity (FB:188-190);
  - text-protocol verbs with "no verb that sends text" (FB:321-330).
  - The baseline today: `FeedbackSend` writes `account_feedback` in plaintext (`server/model/account_feedback_model.go:39`), and log bundles are kept for 7 days (`server/controller/log_file_controller.go:32`).

### 2.5 Pricing and tiers

| Item | PLAN.md | Other source | Conflict |
|---|---|---|---|
| Tier names | Community / Pro / Team (PLAN:348-350) | Solo / Team / Assured (P5:844-846). The server has `free` ("Free (Community)") and `pro` ("UR Pro") only (`config/all/pro.yml:85,96`; `server/model/pro.go:74-75`). The phone shows "Supporter · $5/mo" (M:509), matching `SubscriptionTypeSupporter` (`server/model/subscription_model.go:5695`) and `monthly: 5` (`config/all/pro.yml:106`) | No Team or Assured tier exists in code, and naming differs |
| Team price | "$100/month+usage based overage" (PLAN:350) | "$20–40 / seat*", with * meaning inference (P5:845, 879); $8–25 band (M2:809; `sidecar/sentiment2.md:85`) | Flat price against per-seat |
| recURd scope | "recurd [all]" on every tier (PLAN:360) | Solo has the vault, restore, handoffs, forwards and model access. The signed ledger, attribution, reach receipts, SSO/SCIM and exports are Team (P5:844-845) | Ledger gating |
| Storage | 1 / 20 / 200 GB (PLAN:355) | 1 GB free / 100 GB pro (UI:87-89); "storage… metered" (P5:849) | Pro quota |
| Email/day | 5 / 200 / 20000 (PLAN:356) | "only replies if free", "2000/day if pro" (UI:76-78) | Free and Pro |
| DNS entries | 5 / 200 / 2000 (PLAN:357) | "Unlimited subdomains" (UI:105) | Count |
| TLS edge | 1 / 20 / 200 (PLAN:358) | The TLS edge is the "Team layer" (P5:695, 899) | Free and Pro get the edge in PLAN |
| Metering | "[all of these count towards transfer balance]" (PLAN:353) | "Agents are never metered; storage, edge traffic, and mail are." (P5:849) | Counts against bytes |
| Custom domain, SSO | Team only (PLAN:363-364) | Email "on your own domain" (P5:705); edge and inbox default to the customer domain (M2:553) | Default domain for recURd |
| Feedback | none | "Minimum priority request price $20 [developed]/$2 [other]", "Pro users get 2 free" (UI:153-154) | Absent from FB |

Today's baselines: free has 2 concurrent clients and 30 GiB a day; pro has 1000 concurrent clients and 10 TiB a month, at $5/month or $40/year, or $0.50/$4 on the regional tier (`config/all/pro.yml:86-176`). PLAN:350 and Gmail's bulk rules interact. inference: 20000 sends a day can exceed Google's threshold of "more than 5,000 messages per day to Gmail accounts". Bulk senders then need DMARC, alignment and one-click unsubscribe, and every sender must keep spam "below 0.3%" (https://support.google.com/a/answer/81126).

### 2.6 Trust and privacy promises (exact quotes)

- "Private from us. Actions and approvals complete for your admins. Sessions stay with their author unless shared." (P5:579; also M2:862)
- "Admins see actions and approvals, not transcripts. Sessions open only when the developer shares them, and every admin read is visible to the developer." (P5:640)
- "Between the two sidecars. The relay carries only ciphertext." (P5:681). "Agents reach only granted ranges, and leave only through exits you run." (P5:689)
- "TLS passthrough. The certificate key stays in the sidecar." (P5:699). "Any mode that terminates TLS is labeled as one URnetwork can read." (M2:495)
- "End to end between members. Outside mail is encrypted on arrival." (P5:708)
- "recURd's relay and storage hold no key, so a subpoena or breach yields only ciphertext and the metadata listed here… Where it ends: a hosted model sees what the harness sends unless you run it; outside mail is ordinary SMTP; signed membership stops a breached server adding a reader." (P5:745)
- "Paid: relays, storage, and an edge we run and cannot read" (P5:811). "A plain statement: recURd has no token, and uses URnetwork's network only for worldwide reach." (P5:934)
- "recURd — and URnetwork — never see your code, sessions, or approvals in the clear." (`sidecar/cold5/README.md:16`)
- "Nothing leaves the machine unencrypted — the raw session goes to your vault, a signed entry to the team ledger." (R:932). The login screen shows an "End-to-end encrypted" badge (R:718).
- "the coordination network transports it but never reads it." (T:814). "even URnetwork's coordination servers can't add a reader to your team." (T:940)
- "URnetwork can see membership metadata — that a device joined and when — but never your team's content or record." (T:1010). But T:917 says "the network never sees connection metadata to evaluate", which conflicts with P5:745's "metadata listed here" and with TS:117.
- Feedback: "Feedback is the one thing recURd does read" (FB:11); "This isn't blindness, and public wording must not imply it." (FB:238). Admins read members' feedback (FB:116).
- Admins read "actions, approvals, change-set hashes, the inventory, cost, and coverage"; content pointers resolve "only when the developer discloses" (M2:484). Content is retained only through "a visible audit member" or "disclosed key escrow", and "Never: a silent plaintext archive" (M2:487-491). There are no leaderboards (M2:774).

### 2.7 Code facts that bound the design

- **Plans.** `server/model/pro.go:15-17` is the "single source of truth" for plan limits, read from `config/<env>/pro.yml`. Concurrent-client enforcement turned on 2026-11-03 (`config/all/pro.yml:54-57`). "only top-level clients count" (`server/model/peer_model.go:1528`).
- **Network model.**
  - A network has one `admin_user_id` (`server/db_migrations.go:351-358`), and `network_user` has no network id ("FIXME add network_id", `server/db_migrations.go:376-391`).
  - Network names are 5–50 characters of `[a-z0-9-]`, with no check against a leading or trailing hyphen or `xn--` (`server/model/network_model.go:178-205`). inference: some legal names are invalid DNS labels.
  - A rename releases the old name after a 24 h cool-down (`server/controller/account_controller.go:13,159-171,238-252`).
- **Auth.**
  - Auth types are password, apple, google, bringyour, guest, solana, bittensor and seedphrase (`server/model/auth_model.go:35-42`). Sign-in from a customer IdP and SCIM do not exist; a grep found no SCIM code.
  - URnetwork is itself an OAuth 2.1 / OpenID Connect issuer, at `https://auth.bringyour.com` (`server/IDP.md:1-25`; `server/oauth/oauth.go:3`). It supports client-ID metadata documents and dynamic registration (`server/oauth/client.go:3-15`).
  - API keys are `urn_…` bearer secrets (`server/apikey/apikey.go:113`) with no scope or expiry columns (`server/db_migrations.go:2872-2881`).
- **Transport.**
  - Per-peer TLS prefers `X25519MLKEM768` and falls back to X25519 "if the peer doesn't advertise the hybrid group" (`connect/transfer_encrypt.go:377-385`).
  - Peer identity is "verified at the sequence layer against the contract's `ProvideTlsCertificate` commitment" (`connect/transfer_encrypt.go:395-396`), and certificate chains are signed with the long-lived client identity key (`connect/transfer_encrypt.go:3455-3475`).
- **SMTP through providers.** "Port 25 is deliberately local-only. Port 465 must begin with a TLS ClientHello; port 587… STARTTLS" (`connect/ip_smtp_policy.go:16-22`). inference: MX delivery and reception need URnetwork-run SMTP hosts.
- **Edge.** The nginx build requires `--with-stream_ssl_preread_module` (`warp/warpctl/config_test.go:941`), and a `stream {}` block is generated (`warp/warpctl/config.go:1376-1391`). No `ssl_preread` routing appears in the non-test code.
- **Extension.** MV3 with a `service_worker` (`extension/manifest.config.ts:12,35-42`). The sdk wasm is "tens of MB", and "The service worker never loads it" (`extension/src/utils/sdk-wasm.ts:1-10`).
- **sdk.** No port-forward code found by grep. The Merkle tree uses sorted pairs (`sdk/sn/merkle/merkle.go:14`), so it cannot prove append-only (REC:241). "trail" already names validator leaves (`sdk/sn/merkle/trail_leaf.go:3`).

## 3. Constraints the design must respect

1. New pieces, MLS included, live in the sidecar repo. sidecar depends on connect but not on server or sdk, and server and sdk import sidecar (PLAN:7, PLAN:13; relayed user request). The message repo and `connect/MESSAGEREVIEW.md` are excluded, which voids M2:593's URmessage carrier.
2. Every server-side store holds ciphertext plus a published list of metadata: paths, names, envelope recipients and so on (P5:745, 932). Every cleartext field must be either encrypted or put on that list.
3. Policy, membership and approvals are resolved under customer keys and enforced on the client. The network transports them blind (T:814, 940; TS:51, 108-111).
4. TLS for public names terminates in the sidecar. Any mode that terminates at the edge is labelled readable (P5:699; M2:495).
5. Agents never egress through member or provider exits (P5:689; `sidecar/gap.md:286`). Port 25 never crosses providers (`connect/ip_smtp_policy.go:16-22`).
6. The entry format carries salted commitments and per-entry keys from day one (REC:223).
7. Every grant names an approver and an expiry, appears on the record, and is revoked by one switch (R:1563; P5:729).
8. The free tier must run "any number of agents" (P5:659, 844) within the free tier's 2-client limit (`config/all/pro.yml:87`), or that limit changes.
9. Plan limits go through `pro.yml` and `Pro()` only, with no hardcoded numbers (`config/all/pro.yml:3-6`).
10. Enterprise mode is allow-listable: no camouflage, a published allowlist, the relay named on each receipt (EXT:237-251).
11. The sidecar builds for the CLI, for gomobile, and for a browser or extension worker (PLAN:28).
12. No automatic path carries session content: agent feedback uses enumerated fields, and text waits for a person (FB:11-14, 242-252).

## 4. Reusable pieces

- `model.Pro()`, `ProTier`, and `config/all/pro.yml` tiers `free`/`pro` (`server/model/pro.go:15-112`). Add a Team tier and sidecar quotas here.
- `NetworkConcurrentClientsExceeded` and `CanConnectNetworkPeer` (`server/model/peer_model.go:1499-1530`). These are the hook for counting or exempting sidecar clients.
- `ValidateNetworkName` (`server/model/network_model.go:178`) and `ChangeNetworkName` with `networkNameReclaimCooldown` (`server/controller/account_controller.go:13,33`). Zone naming and quarantine attach here.
- The `server/oauth` OAuth 2.1/OIDC issuer (CIMD, dynamic registration, loopback redirects; `server/oauth/oauth.go:3`, `server/oauth/client.go:3-133`; design in `server/IDP.md`), for "Log in with URnetwork" (R:712-714) and OAuth clients. `apikey.GetNetworkByApiKey` (`server/apikey/apikey.go:20`) is a baseline to replace with scoped, expiring keys.
- `connect.DefaultSequencePostQuantumCurves` and the client-identity-signed certificate chain (`connect/transfer_encrypt.go:382-385, 3455-3475`).
- connect's SMTP egress guard, `smtpRoutesLocally` and `smtpEgressGuard` (`connect/ip_smtp_policy.go:53-70,195`).
- The gVisor netstack in connect (`connect/go.mod:35`, `connect/tun.go`), for userspace reach in cloud containers. inference: it fits environments without a TUN device.
- The nginx stream block and the compiled `ssl_preread` module in warp (`warp/warpctl/config.go:1376`), for SNI passthrough.
- `FeedbackSend` and `FeedbackLogRetention` (`server/model/account_feedback_model.go:39`; `server/controller/log_file_controller.go:32`) as the feedback baseline.
- Mock vocabularies to adopt as schemas:
  - HuJSON grants and autogroups (T:835-880);
  - auth-key properties and OAuth scopes (T:674-748);
  - roles (T:1118-1124);
  - harness YAML (R:1728-1760);
  - ledger entry types (M2:712-723);
  - the feedback API (FB:280-330).

## 5. Gaps, risks, surprises

1. **Unencrypted paths leak work.** inference: with plaintext paths (PLAN:59), the server learns repo layout, file names, alias names and mail folders. FB:230 treats paths and agent or repo names as sensitive.
2. **Server-held rules vs key-authority policy.** PLAN:119 stores rules on the server, against T:814. Signed membership depends on §13.1 (`sidecar/mocks/index.html:103`). Peer identity today rests on server-delivered contracts (`connect/transfer_encrypt.go:395-396`).
3. **Inbound SMTP has no edge.** PLAN's SMTP edge only sends (PLAN:87-97). inference: STARTTLS happens before RCPT, so routing by recipient needs either the sender's SNI or an edge that reads plaintext. "Encrypted on arrival" (P5:708) means the edge sees plaintext the way Proton's servers do: "encrypted with TLS in transit, then stored on our servers with zero-access encryption" (https://proton.me/support/proton-mail-encryption-explained).
4. **The DMARC tie-back assumption is wrong for aggregate reports.** RFC 7489 §7.2 aggregate reports carry counts and authentication results, not Message-IDs. Only §7.3 failure reports carry headers (https://www.rfc-editor.org/rfc/rfc7489.html). That contradicts "message id and routing path are the main DMARC headers" (PLAN:97). The ZK header (PLAN:90-94) is unspecified and research-grade. inference.
5. **Certificates and names.** `ur.network` is absent from PSL version 2026-10-31 (https://publicsuffix.org/list/public_suffix_list.dat). Let's Encrypt allows "50 certificates… per registered domain… every 7 days" (https://letsencrypt.org/docs/rate-limits/). inference: per-network certificates under `ur.network` exceed that quickly, and sibling networks are same-site to browsers. Chrome requires all publicly trusted certificates to be CT-logged (https://googlechrome.github.io/CertificateTransparency/ct_policy.html), so "private per-agent" names such as `*.recurd.dev` (R:1103) become public. EXT:230-233 defers PSL and defaults the enterprise edge to customer domains.
6. **Mixed naming roots.**
   - The mocks use `@brien.ur.network` and `preview.brien.ur.network` (R:1222, 1374) beside `*.recurd.dev` (R:1103).
   - The install commands differ: `ur.io/install.sh … ur up` (T:651) against `recurd.dev/install.sh … ur connect --token urn_…` (R:929-930). The long-lived `urn_` token contradicts T10.
   - The OIDC issuer is on `bringyour.com` (`server/IDP.md`), which Talos files as "Personal VPN" (EXT:23) and which EXT:160-166 keeps off the enterprise path. inference: recurd.dev login may need its own issuer name.
7. **The post-quantum scope is narrower than claimed.** connect falls back to X25519 (`connect/transfer_encrypt.go:377-385`). MLS PQ/hybrid suites are still an Internet-Draft, `draft-ietf-mls-pq-ciphersuites` (https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/).
8. **The extension cannot host a long-lived sidecar.** inference, from the 30 s idle stop above and from today's design, where the service worker never loads the sdk wasm. WebSockets do extend a worker's lifetime (same Chrome page).
9. **Cloud agents.** Codex "blocks internet access during the agent phase" by default (https://learn.chatgpt.com/docs/cloud/internet-access), and "Tailscale is currently the supported VPN provider" (https://learn.chatgpt.com/docs/environments/cloud-environments). The sidecar's endpoints must be allowlistable domains (EXT:172-174).
10. **Scope tensions.**
    - The mock's backtest (R:1639-1640) is an eval feature, which M2:618-620 rules out.
    - Email ships last for recURd (P5:902-904), but it is the core of Burner (M:463-668).
    - Two reach-policy surfaces exist: the harness YAML (R:1743-1749) and HuJSON (T:830-880).
    - FB drops UI:143's "On merge, the chat is final" and UI:153's paid requests.
    - FB:139 cites an owner rule from 10-29 that I could not find in `factury/support/OWNER-DECISIONS-2026-10-29.md`.

## 6. Open questions for the owner

1. **Burner domain.** Which domain carries burners: a shared domain (and which one, since `.ur` does not exist), `<user>.ur.network`, or both? Is cross-alias linkability acceptable on the second?
2. **Offline mail.** When no device is online, is mail queued at an edge, encrypted on arrival, or deferred to sender retries? Does "forwards to you" (M:583) mean forwarding to an outside mailbox?
3. **Paths and rules.** Must evs encrypt paths, and must access rules leave the server for a customer key authority? PLAN:59 and PLAN:119 contradict T:814.
4. **Edge TLS.** Does the TLS edge pass TLS through to the sidecar (P5:699) or terminate it (PLAN:84)? And what about names under `ur.network` before a PSL listing?
5. **Pricing.** Which numbers win: Team at $100/month flat or per seat, the email, storage and TLS quotas, and is the ledger free (PLAN:350-360) or Team-only (P5:845)?
6. **Concurrency.** How do sidecar agents count against `concurrent_clients`: one client per machine, child clients, or exempt?
7. **§13.1.** Is the recURd infrastructure on dedicated `recurd.dev`, or the network only? Do agent identities stay on `@<me>.ur.network`?
8. **Feedback service.** Does the feedback service (FB) live in the sidecar repo with the other new pieces, and are paid priority requests (UI:153) still wanted?
