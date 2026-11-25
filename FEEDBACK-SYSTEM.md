# recURd feedback system: design spec

**Amended 2026-11-24.** DESIGN-COMPUTE.md Appendix J's amendments, by the owner's CO-45 and CO-46 (DESIGN.md's owner decisions 783 and 784), are folded in where each applies, citing its decision and the DESIGN-COMPUTE.md section that holds the detail. The service this spec designs is still not built, and no person's or agent's message reaches it through the support skill until gate G-SUP-service passes (DESIGN-COMPUTE.md §19.2); the sidecar's side that the amendments name is DESIGN-COMPUTE.md §28's, and `support_skill_notes.md` records what of it is built.

**Design only. Nothing in this document is built.** No service, endpoint, schema, CLI command, or `support` subcommand described here exists, and the mockups are static HTML. Names, numbers, and limits are proposals. recURd isn't runnable, so nothing here is a promise to a design partner. Written 2026-11-02 for open item 2 of `factury/HANDOFF-1102-5.md`. The dock's placement and overlap (item 3) are out of scope.

Citations: `R` is `sidecar/mocks/recurd-app.html`, `M` is `sidecar/mocks/urnetwork-mobile.html`, `T` is `sidecar/mocks/team-management.html`, each with line numbers. `pitch5` is `sidecar/pitch5.html`. `UPDATE.md`, `RUN-MAIN.md`, `REPLY-STYLE.md`, and `triage-spec.md` are in `factury/support/`. `[G1]` to `[G5]` mark places that depend on the open §13.1 architecture decision in `connect/EXTENDERUPDATE.md`. They are marked here and listed in §14, not decided.

## 1. Overview

The owner asked for this: anyone submits feedback; it gets an id and joins a feedback log; an internal dev tags it fixed, won't-fix, or in-progress; the status is pushed back to the network's feedback log; agents can submit feedback automatically and track its status.

The trust spine says recURd never sees code, sessions, or approvals in the clear. Feedback is the one thing recURd does read, so the design holds two lines:

1. A person's message reaches recURd only because that person chose to send it, after being told who will read it.
2. The auto tier keeps its closed schema, so no automatic report has a field that can hold session content. An agent also sends free text, tier `agent`: without a person from a clean run, one that has read nothing untrusted, carries no `private` mark, and names no file; and from a tainted run when the device's safety classifier approves. Otherwise the person decides, and a message they approve goes as tier `released` (CO-45; DESIGN-COMPUTE.md §28.5, §28.8).

```
person: dock, phone, web form, CLI on /dev/tty ┐
agent: free text, clean run or approved ───────┤ text, read in full (§10.2)
agent: report via sidecar, closed schema ──────┤ enumerated fields only
                                               ▼
                                 feedback service [G1]: ids, events, status
                                    │                         │
                        network log (one per network)    public board, update cards
                                    │
                dock, phone, sidecar, vault or ledger copy, notifications
                                    ▲
                dev tags status in the triage workspace (today's analogue: factury/support, §13)
```

An **entry** is one report from one submitter (`#100171`). A **board item** is a canonical item, written by a dev, that many entries can link to (`#R-204`). A **network** is a URnetwork account (`brien.ur.network`, M:800).

## 2. Where the mockups map

| Mock element | Where | Spec |
|---|---|---|
| Dock launcher, unread dot, "live · recURd team" | R:852-854, R:658, R:858, R:1927 | §7 |
| Update cards and the streamed new card | R:1895-1901, R:1907, R:1923-1930 | §4, §6, §7 |
| Dock composer; phone Feedback tab and thread; "Support: Chat with factury" | R:862-865, R:1917-1920, M:493-503, M:758-792, M:814 | §5 |
| User's bubble with status chip; dock chip vocabulary | R:1897, R:1900, R:1910, R:1904 | §6 |
| "recURd team" reply; dev progress messages in the thread | R:1898, R:1911, M:769, M:772 | §4 `note` event, §6 |
| Id tags `#8152`, `#8171`, and `#R-204` on "the request board" | M:499, M:766, M:776, M:778 | §3, §8 |
| Chips: Received, In progress, Fixed in 2.31, Not planned | M:102-105, M:766, M:769, M:772, M:778, M:791 | §6 |
| "Logged as #…" acknowledgement | M:766, M:776 | §7 |
| "forwarded with your screenshot" | M:499, M:776 | §9 |
| `ur connect --token urn_…`, auth keys, OAuth clients, `tag:recurd` and its default grant | R:930, T:667, T:705, T:727, T:862-866 | §5 |
| Agent address `<agent>@brien.ur.network` | R:924 | §10.3: never sent |
| Roles, audit log, SIEM stream | T:1117-1125, T:1022, T:1029 | §4, §7 |

**Where the spec departs from the mockups.** The mockups aren't changed; these are for their next iteration.

| Mock shows | Spec says | Why |
|---|---|---|
| Dock bubbles carry no id (R:1910) | Every entry shows its id | The owner asked for ids, and people and agents need one to quote |
| A sent item turns "In progress" after 2.6 s (R:1921) | Demo timer only; only a dev moves status (§6) | Otherwise every report claims work has started |
| "Shipped", red "Won't do" (R:1904); "Fixed in 2.31", muted "Not planned" (M:105, M:772, M:778) | One set of labels, the phone's, muted (§6) | "Shipped" is also a changelog tag (R:1895), and declining isn't an error |
| `#8152` and `#8171` sit in the inbox's real id range | Six-digit ids from their own counter (§3) | Customers must not see inbox ids (RUN-MAIN.md §5, rule 9) |
| "Logged as #8152 and routed to the maps team" in one message (M:766) | The acknowledgement has only the id; routing is a later note | The acknowledgement is synchronous, holding only the id and `received` (§7); routing is triage's lookup (§13), though the service can read the body (§10.2) |
| "forwarded with your screenshot", but no attach control in either composer (R:862-865, M:781) | Attachments per §9; the control needs drawing | |
| No chip for praise, answered questions, or spam | Adds `closed` (§6) | 64% of the inbox is `other` (§13) |
| Sender "factury", "typically replies in minutes", typing dots (M:495, M:500, M:762, M:779) | "URnetwork support" or "recURd team"; no reply time, no live presence | `factury` is a private repo and a rejected product name; the reply time is unsupported today (§13) |
| Agent chat placeholder "Send an instruction or feedback…" (R:881) | That text goes to the agent, never to this system | The wording could mislead |

## 3. Ids

| Id | Form | Names | Allocated by | Grants access? |
|---|---|---|---|---|
| Entry | `#100171`, wire `"100171"` | One report | The service on accept; one counter across products, from 100001 | No; every read is checked |
| Board item | `#R-204`, plus `product` on the wire | One canonical request or known bug | A dev; one counter per board [G5] | No; public unless staff-only |
| `track_token` | 128-bit random, in a link | Anonymous submitter's read access | The service | Yes, that entry's status and notes |
| `agent_ref` | The agent's registered name and where it runs, shown with its messages | One agent, which the platform reads with each message (CO-46; DESIGN-COMPUTE.md §28.5, §28.10). An auto report's stays opaque, keyed under a network-held secret so the service can't recover the name, since §10.3's schema stands | The sidecar | No |
| `fingerprint` | `f_` plus 16 hex, not shown | A group of auto reports: hash of product, component, code | The service, from enumerated fields only | No |

An event is named by its entry plus `seq` (`100171.4`). `client_ref` is a ULID the client generates for retries. The entry number isn't the inbox id, though the mock's values look like one. Customer messages must never show inbox ids (RUN-MAIN.md §5, rule 9). Inbox ids are allocated in batches by `support update` (UPDATE.md:36), while the mock acknowledges at once (M:776). They also number every source, so they'd expose support volume. Six digits tell a dev at a glance which space a bare number is in: at today's inbox growth the ranges won't meet for about two decades. A sequential number still shows total feedback volume to anyone who submits twice, as GitHub and Nolt numbers do (§15).

## 4. The log

The log is one append-only event stream held by the service. Everything else derives from it.

```yaml
event:
  entry: "100171"
  seq: 3
  type: "status"              # submitted, status, fixed_in, note, followup, linked, merged, attachment, deleted
  from: "received"
  to: "in_progress"
  note: "Reproduced behind a captive portal. Working on a fix."   # dev-written, shown to the submitter
  by: "team"                  # what clients see; the dev's identity stays in the triage view
  at: "2026-11-02T10:40:00Z"
  sig: "..."                  # service signature, so a ledger copy stays checkable
entry:                        # current state, derived from the events
  id: "100171"
  product: "recurd"           # recurd or urnetwork
  tier: "human"               # human, released, agent, or auto (§5)
  surface: "dock"             # dock, phone, web, cli, or agent
  kind: "bug"                 # bug, feature, question, praise, security, other; a hint triage may change
  network: "01a19c..."        # null when anonymous [G4]
  submitter: "member:01a1..." # member:<id>, agent:<agent_ref>, or anonymous
  body: "..."                 # the text as sent, not sealed (§10.2); null on the auto tier, which has report instead (§10.3)
  status: "in_progress"       # plus reason and fixed_in (§6)
  board: "R-204"              # or merged_into (§8)
  seq: 3                      # plus client, attachments, created, updated
```

A board item has `id`, `product`, `title`, `text`, `status`, `fixed_in`, and `visibility` (public or staff). An update card has `tag`, `title`, `detail`, `date`, and `board` (R:1895). The stream has three views:

- **Network log:** every entry and event from one network. This spec reads "the network's feedback log" as this view, so status is pushed back to the log of the network that submitted (§15 has the other reading).
- **Public board:** board items and update cards, all written by devs. Entry text never appears here by itself, and `kind: security` never links to a public item until a dev chooses to publish; a `visibility: staff` item still fans status out to its reporters. [G5]
- **Triage view:** all entries, their bodies, and internal notes.

| Reader | Can read | Through |
|---|---|---|
| Anyone | Public board items, update cards | Public page, dock cards |
| The person who submitted | Their entries, and in their `product: urnetwork` thread their agents' as well (§5): body, attachments, every event | Dock, phone thread, `ur feedback` |
| Anonymous submitter | That entry's status and notes, with the `track_token`; the text only in the browser that sent it | Tracking link |
| Agent | The entries it sent: their status, and their messages and replies, whose text it gets only by a read that taints its run first (§7). Its member's whole thread, the person's messages included, only in a run the person is attached to. With `feedback:read:network`, other agents' auto reports in its network (CO-45; DESIGN-COMPUTE.md §28.5, §28.9) | Sidecar |
| Team Owner, Admin (T:1117-1125) | Kind 30's projection of each message and event from the team's network: time, direction, entry, tier, size, and writer, never the text (team copy, below) | Ledger, audit log [G3] |
| Team auditor (T:1117-1125), DESIGN.md's audit reader | The text, bundle manifests, and files in a member's vault. Each read is receipted to the member first, so it's visible to that member, as pitch5 p. 2 promises for sessions | Member's vault [G3] |
| Other team members | Their own entries, and the public board | Dock, phone |
| Devs | The triage view | Triage workspace |
| Other networks | The public board only | Public page |

**Team copy.** As with every other action in the product, this is one write, in the form DESIGN.md's owner-bound vault gives it (owner decisions 63 and 126; DESIGN-COMPUTE.md §28.11, §28.12). The client that sends a message, or receives an event on it, records it as RECORD.md's kind 30, `support_message`, in the member's vault under the member's keys, with the exact text. On a team network the ledger, DESIGN.md's team record, holds kind 30's projection: each message's time, direction, entry, tier, size, and writer, never its text. Owners and Admins read the projection. The team's audit reader, DESIGN.md's visible audit member (owner decision 63), opens the text, the bundles' manifests, and the files in the member's vault, first depositing a `read` entry the member's devices ingest, so the member sees each read. That settles the form G3 left open for the team copy; G3's other questions stay open (§14). The service holds no key and can't do this itself. It's also how a person's own text reaches their other devices. A modified client could skip the copy, but the network log still shows the entry exists, so the gap is visible. The ledger ships with the team layer (pitch5 p. 6); until then only the vault copy exists.

## 5. Submission paths

| Path | Who | Auth | Tier | Mock |
|---|---|---|---|---|
| Dock composer | Signed-in person on recurd.dev | URnetwork login (R:1936) | human | R:862-865 |
| Phone Feedback tab | Signed-in person in the app | App session | human | M:502, M:781 |
| Public web form | Anyone, no account | Proof-of-work stamp (§11); optional email, verified before use | human, anonymous | None |
| `ur feedback send` | A person at a terminal no run binds, or a harness's process | The person's own, confirmed on /dev/tty; from a harness's process, its run's message, which asks the person (point 1) | human; from a harness's process, released | None |
| `support_send` | Agent | The sidecar's support client sends it under its token, scope `feedback:send`: without a person from a clean run, otherwise under kind 27, the classifier or the person deciding (DESIGN-COMPUTE.md §28.8) | agent, or released once a person approved it | None |
| `feedback.report` | Agent, or the sidecar itself | Agent token, scope `feedback:auto` | auto | None |

- **human:** free text typed in a session only a person holds, or at a terminal no run binds, confirmed on /dev/tty. Not sealed (§10.2). Attachments allowed.
- **released:** an agent's message a person approved through outward kind 27, `support_send`, the decision its receipt (DESIGN-COMPUTE.md §16.3, §28.8). It replaces the draft: a message that needs a person waits as kind 27's request, whose card shows it whole, and the person's approval sends it.
- **agent:** an agent's free text sent without a person: from a clean run, or approved by the device's safety classifier. The message also says whether its run was tainted and who approved it (CO-45; DESIGN-COMPUTE.md §28.5, §28.8).
- **auto:** no free text, closed schema (§10.3). No person in the loop once the grant is on.

1. **The CLI's text is the person's only at a terminal no run binds,** where `ur feedback send`, `ur support send` in DESIGN-COMPUTE.md §28.4, is confirmed on /dev/tty (DESIGN.md §5.8). From a harness's process it is that run's message, under outward kind 27, which always asks the person, since the device's classifier never saw what the harness read. Drafts and `ur feedback release` retire: where a person is needed, the message waits as kind 27's request, and the person's decision is its receipt (CO-45; DESIGN-COMPUTE.md §28.4, §28.8). An agent driving a person's logged-in browser defeats this, as it does every approval flow.
2. **Agent credentials stay in the sidecar.** It mints a token of at most an hour from the agent's enrolled identity (`ur connect`, R:930), or from a team auth key or OAuth client for headless fleets (T:705, T:727). Tokens are bound to the sidecar's key and never enter the agent's environment. Scopes: `feedback:auto`, `feedback:send` for tier `agent`'s bodies, `feedback:read:own`, `feedback:read:network`; and `scope=member` lets a member's device read its member's whole conversation (§12). The token rule stands for them all (DESIGN.md R-CTX-9): the sidecar's support client holds the token, never an agent (CO-45; DESIGN-COMPUTE.md §28.4, §28.9). The `ur` binary and token flow are placeholders (`mocks/index.html:101`). Any new credential path owes the admin email notice under the owner's 10-29 rule. [G3]
3. **Auto is off by default.** `feedback.auto` is a grant a person turns on per network or per agent, with an expiry, on the record, and removed by the one switch that revokes an agent's reach (pitch5 p. 3). The default policy gives `tag:recurd` agents no route past their own team record (T:862-866), which fits: no grant, no report. Whether the grant lives in that policy file is [G3].
4. **Team policy.** A team admin sets `feedback.egress` as the network's compute block's `support` (CO-45; DESIGN-COMPUTE.md §16.4, §28.6): its `egress` is `on`, the default, `persons` (people's own messages and enumerated reports, no agent's), `auto_only`, or `off`, and beside it `agents` and `logs`, each true by default, say whether the network's agents may write to support and attach the support log (§9). It's enforced in the client and shown in the composer, and it only narrows the person's own `support` key, which only the person's own act writes. It lets a team narrow what its members and their agents send to support (DESIGN-COMPUTE.md §28.11).
5. **Other paths.** Self-hosted and air-gapped installs send nothing; `ur feedback export` writes a bundle a person can send by any path. support@ur.io, GitHub issues, and feedback.ur.io keep flowing into the inbox, with no `#` id unless a dev links them to a board item.

Each person has one thread per product, so the phone tab and the "Chat with factury" row (M:814) open the same one. The dock files under `product: recurd`; the phone tab, whose header says URnetwork support (M:762), files under `product: urnetwork` (§13). Every agent of the member writes into that `product: urnetwork` thread, on any of the member's devices, in their agents' enclaves, or by a tagged sidecar they sponsor, each message labeled with the agent's name (§3), so the person sees every message and reply in one place and support answers one customer (CO-45; Q-SUP-1, Q-SUP-2; DESIGN-COMPUTE.md §28.5).

## 6. Status model

| Status | Meaning | Owner's word | Label on every surface | `final` |
|---|---|---|---|---|
| `received` | Accepted, id assigned, nobody has committed to anything | (from the mock) | Received | No |
| `in_progress` | A dev is working on it | in-progress | In progress | No |
| `fixed` | The fix is merged; `fixed_in` says where | fixed | Fixed in 2.31, or Fixed, in the next version | Once `fixed_in` isn't `next` |
| `wont_fix` | Decided against, for now | won't-fix | Not planned | Yes, but reversible |
| `closed` | Nothing to act on: praise, an answered question, spam | (added here) | Closed | Yes |

```
received    → in_progress, fixed, wont_fix, closed
in_progress → fixed, wont_fix, received (work stopped; note required)
fixed       → in_progress (reopened; note required)
wont_fix    → in_progress, fixed (reconsidered; note required)
closed      → received (closed by mistake)
```

1. **Only a dev moves status.** Submitters and agents can add a `followup`, which re-queues triage and leaves the chip alone. Triage alone changes nothing the submitter sees. Partial work is `in_progress`, with a note saying what's done.
2. **`fixed` needs `fixed_in`:** a release (`2.31`), `next`, or `server:<date>` once a server fix is deployed. A dev sets it only after the merge. `next` follows the existing rule that a merged fix is "fixed, in the next version", with no date (RUN-MAIN.md §5, rule 4; REPLY-STYLE.md:38). Moving from `next` to a release is a `fixed_in` event.
3. **`wont_fix` needs a note and can be reversed.** The mock says "not planned for the next release" about an item that stays on the board (M:778).
4. **`closed` carries a `reason`:** `answered`, `thanks`, or `not_actionable`. `not_actionable` covers spam, probes, and items that fail the honesty review, and it's silent.
5. **Stale writes are refused.** A dev's update carries `expected_seq`, and a stale one gets 409, so two tools can't both move an entry (§13).
6. **No automatic reopen.** An auto report from a version at or past `fixed_in` sets `regressed: true` and queues triage.

**Board items** have the same five statuses. A linked entry follows its board item's status and `fixed_in`, each change arriving as an event on the entry, so a board item's note must be written for everyone linked to it. **Update cards** (Shipped, Fixed, New, Improved, R:1907) describe releases, not entries; a dev writes each one, and a status change doesn't publish a card.

## 7. Pushing status back and telling people

1. A dev tags the entry in the triage workspace (§12). The service checks the transition and `expected_seq`, appends a signed event, and fans out to linked entries if it's a board item.
2. The event is now in the network log, the source of truth. Everything after this is delivery, so a lost push loses nothing. (The acknowledgement of a submission is separate: synchronous, holding only the id and `received`.)
3. Clients with a live connection get the event on the stream they hold open [G2]; the rest catch up from a cursor on reconnect. Delivery is at least once and ordered per entry, and clients drop repeats by entry and `seq`. The service never dials a client, except a webhook a team admin set up.
4. The receiving client copies the event into the vault or ledger under its own keys.

| Recipient | Online | Offline | Mock |
|---|---|---|---|
| Person in the dock | Chip updates in place, note bubble | Red dot on the launcher while collapsed; catches up on load; email if opted in | R:658, R:1915, R:1927 |
| Person on the phone | New bubble with chip | The `support` push hint wakes the app, which composes its own notification, such as "URnetwork support replied on #100171", with no reply text. This also reaches phone and wallet accounts, which have no address and get no reply today (RUN-MAIN.md §5, rule 8) | M:769, M:772 |
| Anonymous submitter | Tracking page | Email only if the address was verified | None |
| Running agent | A `support_update` event, which queues a notice for its next turn and wakes it in an open run, within the wake limits; MCP's `resources/updated` on `ur://support/urnetwork`; a `ur support watch` line | A notice in its own inbox, `agent/<name>`, which the Harness takes when the run reopens | None |
| Team admin | Audit view, SIEM stream, webhook: ids and statuses, no bodies | Same | T:1029 |

- **Mail and push carry no content:** mail holds the id, status, `fixed_in`, and a link; the `support` push hint holds only `{product, entry, seq}`, and the app composes the words (CO-45; DESIGN-COMPUTE.md §28.9). Mail is ordinary SMTP (pitch5 p. 3), and Apple and Google see push payloads.
- **Email is opt-in, for status changes only, to verified addresses.** Anonymous addresses need a confirmed link first; otherwise the web form becomes a way to mail strangers.
- **Status mail must not put sign-in at risk.** A fix to a large board item could mail thousands of people, and sign-in codes share the SES account today, so a complaint spike could lock every user out (RUN-MAIN.md §5, rule 7). Sends are digested, capped per run, held to that rule's stop limits, and need their own sending identity. [G5]
- **A status event is information, not an instruction.** The sidecar never acts on one. What tells an agent carries only enumerated values, `{product, entry, seq, type, status, fixed_in, final}`, rendered from them and never as text, so taking a notice taints nothing. A reply's text reaches an agent only by a read that taints its run first (`support_read`, `ur support show`, `ur support watch --notes`), between untrusted-data markers and labeled as support's: outside input, the rule pitch5 p. 3 applies to outside mail (CO-45; DESIGN-COMPUTE.md §28.9).

## 8. Deduplication

| Layer | Trigger | Decided by | Result |
|---|---|---|---|
| Retry | Same `client_ref` from the same submitter within 7 days | Service | Same id, `replayed: true` |
| Repeat auto report | Same `fingerprint` from the same network | Service | Same id, `coalesced: true`, occurrences go up. Once the entry is final, the sidecar stops sending it until its own version changes |
| Known auto report | `fingerprint` a dev linked to a board item | Service | New entries link at submit; entries stay separate per network |
| Person's text | A dev recognizes a duplicate | Triage | `merged_into` within a network, or `board` across networks |
| Before sending | Composer searches a downloaded copy of the public board | Client | "Looks like #R-204"; the text isn't sent to do this |

- People's messages never merge automatically, though the service can now read them (§10.2): a wrong merge would tell someone their problem is fixed when it isn't.
- A merge never exposes one network's text to another. Across networks the only link is a board item, whose text a dev wrote. The merged entry keeps its id, shows "Merged into #R-204", and follows that status.

## 9. Attachments and logs

| Type | Who | Limit | Kept |
|---|---|---|---|
| Screenshot, PNG or JPEG | A signed-in person | 3 per entry, 10 MB each | 180 days after the entry is final |
| Log bundle | A signed-in person, with a checkbox that starts off; never an agent | 1 per network per 5 min, 100 MiB, as the server does today | 7 days, as `FeedbackLogRetention` does today |
| Support log bundle | An agent with `logs: true`, or a person | 1 per message, 4 MiB; 1 per network per 5 min | 7 days |
| A file an agent names: UTF-8 text, PNG, or JPEG | An agent, only with the person's approval | 3 per message, 10 MiB each | 180 days after the entry is final |

- **Anything else is refused, and anonymous submitters attach nothing.** An agent attaches the support log's bundle, content-free by construction, and files only with the person's approval: a file always waits as kind 27's request, rule `attachment`, whose card shows each file whole, and the classifier never decides one (CO-45; DESIGN-COMPUTE.md §28.7, §28.8, §28.14).
- **Attachments aren't sealed, as bodies aren't (§10.2),** and a person sees what's going first: the image, or the list of log files. The person can also read any support-log bundle whole, the next one or one already sent (`ur feedback preview`). Screenshots are never captured automatically, because a screenshot of recURd shows agent, repo, and file names.
- **recURd's logs must be content-free at the source:** registry codes and enumerated fields, no prompt text, tool arguments, or paths. Today's redactor can't provide this. It maps IPs and uuid-shaped ids to tokens and leaves message text as written (`sdk/diagnostics_redact.go`), and the upload path calls it only on the special files, sending glog files as written (`sdk/log_upload.go`; DESIGN-COMPUTE.md §28.3). The support log meets the rule by construction: registry codes and typed fields written through an API that takes no free text, tokens salted per bundle, and each bundle assembled outside every agent's context, so no agent reads it (DESIGN-COMPUTE.md §28.7).
- **Attachments are hostile by default.** Inbox item 1049 holds a root-CA installer and a BIOS image. Triage decodes images in a sandbox and reads log bundles only through a parser for a fixed line format, in line with RUN-MAIN.md §9.

## 10. Privacy

### 10.1 What's visible to whom

| Content | Relays, providers | Service storage | Devs, triage tools | Submitter | Team admins | Everyone else |
|---|---|---|---|---|---|---|
| A person's or an agent's text, files, logs | Ciphertext (TLS) | Plaintext (§10.2) | Plaintext | Yes | Kind 30's projection; the text to the auditor, by receipt (§4) [G3] | No |
| Auto report fields | Ciphertext (TLS) | Plaintext | Plaintext, grouped by fingerprint | Yes | Yes, team copy | No |
| Status events, dev notes | Ciphertext (TLS) | Plaintext | Plaintext | Yes | Status, yes; a note's text to the auditor, by receipt (§4) | No |
| Board items, update cards | Ciphertext (TLS) | Plaintext | Plaintext | Yes | Yes | Yes |
| Metadata (§10.4) | Connection metadata [G2] | Yes [G4] | Yes | Their own | Their network's | No |

"The network carries only ciphertext" holds on every path, under either answer to §13.1: every connection is TLS. Bodies aren't sealed, so the service reads them (§10.2). Code, sessions, approvals, prompts, tool arguments, file paths, and agent or repo names have no field on the auto tier. They reach recURd only if a person types or screenshots them into a message, or an agent writes them into one under §5's rules, and then they're in the first row; an agent's message also carries its name (§3). The composer says before sending who will read it and not to paste code or secrets. A client-side scan flags likely secrets, paths, and hostnames. On a person's message it warns, and the person decides. On an agent's message a secret refuses it, `secret_in_message`, naming the pattern's class and the span, never the match, and nothing is sent or queued; the scan reads the text and each text file for the record's redaction patterns, every credential the sidecar holds, and every sign-in code or link the mail component withheld (CO-45; DESIGN-COMPUTE.md §28.6).

Two other parties need disclosing. If triage tools use a hosted model, its provider reads plaintext, and the inbox works this way today: every `log.yml` entry in the checkout read has `author: "claude"`. The owner chose disclosing it over replacing it (CO-46, Q-SUP-10; DESIGN-COMPUTE.md §28.13, §28.15): the triage model's provider, Anthropic today, reads the entries triage gives it, as a subprocessor that `support:urnetwork` names with its retention, under an agreement that bars training on them. Triage gives it only entries sent under a `support:urnetwork` version that names it, the version each message's SupportBody carries (§12), and a new subprocessor or a longer retention is a new version with no grace. The model joins triage only once that agreement is in place and the disclosure names it (DESIGN-COMPUTE.md §28.21). A board on Nolt, or mail through SES and Gmail, is visible to those vendors, but holds only dev-written text and notifications.

### 10.2 Sealing

**Nothing is sealed** (CO-46, the owner's answer to Q-SUP-3: "The support conversation is meant to be fully read by the platform."). Bodies, attachments, and log bundles reach the service over TLS, and the service and the triage workspace read them in full; dev notes stay plaintext at the service, as before. The published triage key, its publication, and the rule that a note never quote a body go (DESIGN-COMPUTE.md §28.10, §28.15). Server-side text search and spam filtering are open to the service.

**This is the one owner-approved exception to the plaintext rule,** the owner directive's rule that no server component sees plaintext content (DESIGN.md's I-2 and §2.8; owner decision 784). The owner: "This is the one owner-approved exception to the plaintext rule. Don't reuse the pattern anywhere else." It is this spec's support conversation's alone: what a person or their agents choose to send to support through this service, and support's replies. Nothing else of the person's reaches the service, no other service or path takes the exception, and no design may cite it as a precedent.

This isn't blindness, and public wording must not imply it; the disclosure says so before the first message (DESIGN-COMPUTE.md §28.13). Devs and their tools read everything sent to them, and a breach of the service, its edge, or the triage workspace, or a legal demand that reaches them, reaches every body, attachment, bundle, and note they hold. The threat model must name the service and the triage workspace as an exception to pitch5 p. 3's "a subpoena or breach yields only ciphertext". What keeps a person's secrets and private data out is on the device: the secret scan (§10.1), the content-free support log (§9), and the person's approval for files and for runs that hold their private data (§5; DESIGN-COMPUTE.md §28.6 to §28.8).

### 10.3 How an agent's automatic report avoids leaking session content

1. **The server enforces it.** A `feedback:auto` token can send only this schema. The sidecar fills it, and an agent can only choose a `code`. Any other field gets 422, so a stolen or misused token still can't carry text.

```
report: registry, component, code, severity (info, degraded, failed), occurrences (1, 2-9, 10-99, 100+), first_seen_day
client: version, os, arch, harness, harness_version    # enumerated or format-checked; plus the opaque agent_ref (§3)
```

2. **Only recURd's own failures have codes.** The registry is a versioned file in the open-source sidecar, so adding a code is a reviewable diff. Harness errors and customer-code errors have no code and can't be reported. There's no message, stack trace, path, hostname, URL, model name, repo name, or agent name; agent names like `billing-audit` (R:1197) describe work.
3. **There's no opaque field to smuggle data in.** The service computes `fingerprint` itself from enumerated values.
4. **The auto tier's closed schema stands, and an agent's free text goes under §5's rules** (CO-45; DESIGN-COMPUTE.md §28.8): without a person from a clean run, by the device's safety classifier or the person from a tainted one, and always by the person for a file or a run that holds the person's private data. Prompt injection can make an agent write session text into a message; a secret the scan finds is refused (§10.1), and a miss by the classifier costs up to 16 KiB of the run's text, read by support and the triage model's provider, within the classifier's limits. On the auto tier the worst it can do is still choose a wrong code.
5. **It's on the record and off until granted.** Every report, and every message an agent sends (§4's kind 30), goes to the vault or ledger with its exact bytes, `ur feedback preview` shows what would be sent, and the code is open.

What an auto report still reveals: this network ran this harness, version, and OS, and hit this code on this day. An adversarial agent could signal a few bits through its choice of codes and timing, bounded by §11 and visible in the ledger. The claim is "no session content", not "no information".

### 10.4 Metadata, retention, deletion

The service sees, for the threat model pitch5 p. 6 promises: network id, submitter ref, product, surface, tier, kind hint, client version, OS, harness, timestamps, body and attachment sizes and types, the notification address if any, and the source IP at the edge. The IP goes only into a salted rate-limit counter that expires within 24 hours and is never stored on the entry. This list is provisional. [G4]

Retention beyond §9: bodies, 180 days after the entry is final; auto report occurrences roll up daily and lose the network link after 180 days; a `track_token` lasts 90 days after final. Drafts, which stayed local for 7 days, retire (§5). A submitter can delete their body and attachments at any time, leaving only the id and status. The team's copy follows the team's retention. Triage copies must follow too, which is why bodies stay out of git (§13).

## 11. Abuse limits

The inbox took roughly 140 to 430 items a month from all sources in 2026, so these starting values can be tight. Limits keyed by network assume the service knows the network. [G4]

| Caller | New entries | Size | Over the limit |
|---|---|---|---|
| Anonymous web | 3 an hour and 10 a day per salted IP bucket, proof of work that hardens under load | 4 KB, no attachments | 429 |
| Signed-in person | 10 an hour and 50 a day | 16 KB, §9 attachments | 429 with `retry_after` |
| Agent, auto | 5 new fingerprints a day per agent, 20 per network; repeats coalesce and don't count | Closed schema | 429; after 3 refusals in a row the sidecar stops reporting for that run |
| Agent, messages (CO-45; DESIGN-COMPUTE.md §28.14) | 5 an hour and 20 a day per agent, 50 a day per network across its agents | 16 KiB; one support-log bundle a message, 4 MiB; files per §9 | 429 with `retry_after`, never queued past it; after 3 refusals in a row the skill stops sending for the run |
| Agent, outbox | 10 messages waiting per agent, 50 per device | | Refused locally, `support_queue_full` |
| Reads | 60 a minute per token, one `subscribe` stream per sidecar | | 429 |
| Email | One per entry per status change, 5 a day per address, then a digest | | Queued |

- **Feedback never blocks work.** Reports queue in the sidecar, up to 100 with the oldest dropped, and a failure doesn't affect the run.
- **No third-party CAPTCHA.** feedback.ur.io's pages already sit behind a Cloudflare challenge (UPDATE.md:67). A challenge shows visitors to a vendor and can turn away people on VPNs or censored networks, who are this network's users. Proof of work costs neither.
- **Hostile input is normal.** The checkout read holds 1,344 spam items and 1,352 marked not eligible. Text renders as text, never HTML. Triage treats entries as data, not instructions (RUN-MAIN.md §9), which matters more because the support agent can land code. With nothing sealed (§10.2), the service can filter spam before it reaches the triage workspace.
- **Probing gets nothing.** Missing and not-yours both return 404. Devs can pause a network's or an agent's submit rights, and the sidecar shows the pause to the admin.

## 12. Agent API sketch

The base is `https://<feedback-host>` [G1]. Agents normally reach this through the sidecar's verbs below, not directly.

```http
POST /v1/entries                               # submit, auto tier
Authorization: Bearer <agent token>            # feedback:auto, bound to the sidecar's key
Idempotency-Key: 01JC9Z7V8K4T2M6R0QWXYZABCD    # client_ref

{ "product": "recurd", "tier": "auto", "agent_ref": "a_7f3c91d2",
  "report": { "registry": "2026-11", "component": "sidecar.relay", "code": "connect_timeout",
              "severity": "degraded", "occurrences": "10-99", "first_seen_day": "2026-11-02" },
  "client": { "version": "0.4.1", "os": "linux", "arch": "arm64", "harness": "claude-code", "harness_version": "2.1" } }

201 { "id": "100171", "status": "received", "seq": 1, "coalesced": false, "board": null, "fixed_in": null }
200 { "id": "100171", "status": "fixed", "seq": 6, "coalesced": true, "board": "R-204", "fixed_in": "0.4.2" }
422 { "error": "field_not_allowed", "field": "report.message" }     # also 403 grant_required, 429 rate_limited with retry_after

POST /v1/entries                               # submit, tier agent (CO-45): one message of the support conversation
Authorization: Bearer <token>                  # feedback:send; the sidecar's support client holds it, never an agent
Idempotency-Key: <client_ref>                  # one per message, which the outbox posts once (DESIGN-COMPUTE.md §28.6)

{ SupportBody }                                # DESIGN-COMPUTE.md §28.10: v, product, client_ref, entry, tier, kind, text, the
                                               # sender with its agent_ref (§3), the bundle's and files' SHA-256 and sizes,
                                               # and the support:urnetwork version it went under

POST /v1/entries/100171/followups              # a message continuing an item, open or final: a followup event (§6)
GET  /v1/entries?client_ref=<client_ref>       # the entry a client_ref made, for an outbox that lost its answer

GET /v1/entries?scope=mine&status=received,in_progress&cursor=<c>&limit=50     # list
200 { "entries": [ { "id": "100171", "status": "in_progress", "fixed_in": null, "final": false,
                     "board": null, "merged_into": null, "seq": 2, "updated": "..." } ], "next": "<c>" }

GET /v1/entries/100171/status                  # get status; ETag is seq, so unchanged gives 304
200 { "id": "100171", "status": "fixed", "fixed_in": "0.4.2", "final": true, "board": "R-204", "seq": 6, "updated": "..." }
404 { "error": "not_found" }                   # the same for missing and not-yours

GET /v1/events?scope=mine&cursor=<c>           # subscribe: server-sent events on a connection the sidecar opens [G2]
event: status
id: 100171.6
data: { "entry": "100171", "seq": 6, "from": "in_progress", "to": "fixed", "fixed_in": "0.4.2", "at": "...", "sig": "..." }

GET /v1/events?scope=member&cursor=<c>         # a member's device: its member's whole conversation (§5)

GET  /v1/public/board?product=recurd           # no auth
GET  /v1/public/updates?since=<c>              # no auth; feeds the dock's cards
POST /v1/triage/entries/100171/status          # dev credential, separate from all customer tokens
     { "to": "fixed", "fixed_in": "next", "note": "...", "expected_seq": 5 }     # a stale seq gets 409
```

- The human and released tiers use the same `POST` with the body as sent, not sealed (§10.2): the human tier under a person's session token, and the released tier naming who approved it, the kind-27 decision that is its receipt (§5); `draft_digest` retires with the drafts. Tier `agent` posts under `feedback:send`, above. A `feedback:auto` token can still send only §10.3's schema.
- `scope=mine` needs `feedback:read:own` and `scope=network` needs `feedback:read:network`. `scope=member` serves a member's device its member's whole conversation, and a tagged sender reads `scope=mine` (DESIGN-COMPUTE.md §28.9). An agent token never receives a person's body.
- An agent's entry names its member's thread beside its `agent_ref` (CO-45; DESIGN-COMPUTE.md §28.6, §28.10, §28.11): the service files each post in the thread of the token's member, a tagged sidecar's in its sponsor's. Each entry keeps the `support:urnetwork` version its message went under, which says whether triage may give it to a hosted model (§10.1).
- The service hints the `support` push topic for each of the member's sidecars, and a tagged sender's own, with `{product, entry, seq}` and never content (§7; DESIGN-COMPUTE.md §28.9).
- `include=note` on `/v1/events` adds note text, labelled as outside input. A team admin can register a webhook, `POST /v1/webhooks { "url", "secret", "scope": "network" }`, whose payload is the same event without notes, HMAC-signed.

Sidecar verbs and CLI, with placeholder names; DESIGN-COMPUTE.md §28.4 gives them as the support skill's tools and `ur support`. An agent's text goes only by `support_send`, under §5's rules, and drafts and `ur feedback release` retire (CO-45).

| Text protocol | CLI | Effect |
|---|---|---|
| `feedback.report code=sidecar.relay/connect_timeout` | `ur feedback report <code>` | Auto-tier submit; returns id and status |
| `support_send(text, entry?, kind?, logs?, files?)` | `ur feedback send <text>` | Sends one message, or with `entry` a follow-up, under §5's rules, answering at once `sent`, `queued`, or `approval_pending`; the CLI's at a terminal no run binds is the person's own, confirmed on /dev/tty |
| `feedback.list`, `feedback.status <id>` | `ur feedback list`, `ur feedback status <id>` | Reads entries and status |
| `feedback.watch [id]` | `ur feedback watch [id]` | Streams status lines; with `--notes`, replies' text, tainting the run first (§7) |
| None | `ur feedback preview`, `ur feedback export` | Shows the exact bytes; writes a bundle (§5) |

## 13. How an entry could map onto the support inbox

Nothing here is built: `support update` has no recURd source, and no command pushes status. This section shows where an entry would fit today's inbox (`factury/support/UPDATE.md`, `triage-spec.md`) and where it doesn't. The checkout read for this spec has 8,168 items, each with a `log.yml`. `other` is 5,256 of them (64%): praise 2,482, spam 1,344, questions 741, support requests 435, automated 213, and a few others. Bugs are 2,362 and feature requests 550. That's why `closed` exists.

| Inbox today | A recURd entry |
|---|---|
| Inbox id, `source`, `source_id`, dedupe on `source_id` (UPDATE.md:13-21) | The item gets an internal inbox id at ingest; `#100171` stays the only id a customer sees. `source: "recurd"`, `source_id: "recurd:100171"`. Follow-ups are `recurd:100171#followup-<n>`, as email does. Auto reports get one item per fingerprint across networks: `recurd-auto:<fingerprint>` |
| `support update` order and cutoffs (UPDATE.md:27, UPDATE.md:37) | A new source at the end of the order; its cutoff is an event cursor, moved only after the source finishes |
| `message.md`, `source.json`, `initial-triage`, `honesty-safety-review` (UPDATE.md:8-10, triage-spec.md) | The same files, entries, and rules; the body stays out of git (below) |
| `Theme <slug>:`, `related_items` (UPDATE.md:95-97) | A theme is the inbox's version of a board item: 2,598 items sit under 35 themes, the largest with 556, each judged once. One worth tracking publicly gets an `R-` item |
| `triage-repos.md`, area to repo | `component` names the area. "Routed to the maps team" (M:766) is this lookup |
| `reply.md`, `support send` over SES (RUN-MAIN.md §5) | A reply becomes a `note` event; mail shrinks to a notification (§7) |

Status goes back out as a deliberate push by a dev or the support agent:

| Inbox state | Entry status |
|---|---|
| `initial-triage`, `open` | No event; stays `received` |
| Work started, or `partial` | `in_progress`, with a note on what's done. `fix` outcome `no-fix` leaves it unchanged, or back to `received` if work stopped |
| `fix` outcome `fixed`, merged to main (logs also show `fixed-pending-release`, `fixed-pending-deploy`) | `fixed`, `fixed_in: next` |
| A release or deploy carries that merge | `fixed_in: 2.31` |
| A dev or the owner declines it | `wont_fix`, with a new log action; the inbox has no won't-fix today |
| `closed`, praise or answered | `closed`, reason `thanks` or `answered` |
| `eligible: false` | `closed`, reason `not_actionable`, silent |

Each push would append `action: "status"` to the item's `log.yml`; 104 logs already use that action, though `triage-spec.md` doesn't define it. The two statuses stay separate on purpose: the inbox judges the code, and the entry says what the submitter has been told.

Where the fit breaks:

1. **Git keeps everything.** Items are committed to factury main (UPDATE.md:106) and history is never rewritten, so no retention or deletion promise can hold for anything committed. A recURd body stays out of git, as unredacted logs do (RUN-MAIN.md §7.2). The directory name uses no words from the body, and `log.yml` paraphrases rather than quotes.
2. **Reply times.** RUN-MAIN.md describes a 15-minute run, but on 11-02 this Mac had no launchd job, cron entry, or `.support` directory for it, and support passes ran by hand. A separate machine wasn't checked. "Typically replies in minutes" (M:495, M:762) has no support today.
3. **Two writers.** On 10-29, parallel agents sent three customers duplicate replies because send guards read only local logs. `expected_seq` gives this channel a server-side guard; the one-owner-per-item rule still applies.
4. **Today's reply rules carry over to notes:** never claim an action that hasn't happened, only the person's own records, no internal details (RUN-MAIN.md §5), the customer's language (REPLY-STYLE.md:18), and the sanctioned-region rule, under which feedback is still recorded and fixed but a note gives only docs and shipped fixes (RUN-MAIN.md §9).
5. **The phone tab today.** `FeedbackSend` writes `account_feedback` in plaintext to Main and returns a `feedback_id`; replies are email only. With the support skill, the app's support conversation moves to this spec's thread for `product: urnetwork` (§5), which its disclosure, `support:urnetwork`, says the platform reads in full, so the tab claims no sealing. The survey form, `FeedbackSend`'s, isn't support and stays as it is (CO-45, CO-46; DESIGN-COMPUTE.md §28.3, §15.4).

## 14. What depends on §13.1

§13.1 asks whether recURd runs on dedicated `recurd.dev` infrastructure or uses URnetwork's network only for worldwide reach, with no dedicated infrastructure. Nothing below decides it. Bare section numbers in the table refer to `connect/EXTENDERUPDATE.md`.

| Tag | What's open | What each answer changes | Where |
|---|---|---|---|
| **G1** | The service's host and name | Dedicated: a `recurd.dev` control name, on the published allowlist (6.3) and checked by preflight (9.2). Network only: likely beside `api.bringyour.com`, which Talos files as Personal VPN, so agents behind some gateways couldn't report or track status | §1, §12 |
| **G2** | The path from client to service, including `subscribe` | Dedicated: customer egress, publicly trusted leaf (7.1), and a ledger row naming the relay (6.4). Network only: URnetwork's network, where extender or provider paths are possible, so the record can't show that no consumer host was in the path. Relays see only ciphertext either way | §7, §10.1, §12 |
| **G3** | Who enforces team readers and `feedback.*` grants | Customer-held keys (signed membership) or the server's policy resolver. The handoff ties the signed-membership claim to §13.1, and `mocks/index.html:103` ties it to blind coordination. Role names and the grant's home may change | §4, §5, §10.1 |
| **G4** | What metadata the service must hold | The spec assumes it sees `network_id`. A blind-coordination answer could replace that with a pseudonym, which changes rate limits and what a dev can see | §4, §10.1, §10.4, §11 |
| **G5** | Where the public board, update feed, and status mail live | Dedicated: `recurd.dev` names, apart from feedback.ur.io and its wallet and payout threads (8.3), mail under DMARC `p=reject` (8.2). Network only: could share feedback.ur.io and today's mail path. The mock's `@brien.ur.network` addresses (R:924) sit on a consumer name, which 6.1 keeps relays off | §3, §4, §7 |

Pitch5's direction 2 (the network-boundary rewrite) is held for the same decision, so public wording about the path waits too. Not gated: ids, the status model, tiers, the auto schema, dedup, attachments, limits, and the inbox mapping.

## 15. Decisions the owner may want to change

Each is what this spec chose, then the alternative. All limits and retention periods are starting values to tune during pilots.

1. **Agents can't send free text automatically.** Reversed by the owner (CO-45; DESIGN-COMPUTE.md §28.8): an agent sends free text without a person from a clean run, and from a tainted one when the device's safety classifier approves, the person deciding otherwise (§1, §5). This spec had chosen enumerated reports only, which narrows "agents can submit automatically", since prompt injection could send session content to recURd; the secret scan's refusal (§10.1), the person's approval for files and for runs that hold their private data (§5), and the limits (§11) now bound what a miss sends.
2. **Auto reports are off until granted.** On by default yields more reports but opens a way out nobody approved.
3. **"The network's feedback log" means a per-network view plus a public board.** A fully public log would need consent and redaction on every entry (RUN-MAIN.md §9 bars customer information in public).
4. **Bodies are sealed to a triage key.** Changed by the owner (CO-46, Q-SUP-3): nothing is sealed, the one owner-approved exception to the plaintext rule (§10.2). This spec had chosen sealing: TLS plus encryption at rest is simpler and allows server-side search and spam filtering, but then a breach of the service yields every message, a much wider exception to pitch5 p. 3's breach sentence.
5. **Team admins can read what members send,** because security buyers must answer what left. A digest-only ledger row gives members more privacy and admins less. Under DESIGN.md's owner-bound vault it takes §4's form: Owners and Admins see kind 30's projection, with no text, and the audit reader opens the text in the member's vault, by receipt (owner decisions 63 and 126; DESIGN-COMPUTE.md §28.11).
6. **Two levels of id, with dev-written public text.** Single-level public entries are simpler but can't keep cross-network dedup private.
7. **Six-digit sequential ids, separate from the inbox.** A random `#7KQ2M9XD` wouldn't reveal volume, but it's harder to read and further from the mock.
8. **`closed` is a fifth status.** Otherwise praise and spam sit at `received` forever, and a tracker never finishes.
9. **`fixed` needs `fixed_in`, and the phone's labels win.** The dock's "Shipped" and "Won't do" could stay if preferred.
10. **CLI free text is the person's own at a terminal no run binds, confirmed on /dev/tty, and a harness process's is its run's, under kind 27** (CO-45; DESIGN.md §5.8; DESIGN-COMPUTE.md §28.4, §28.8). It replaces this spec's release elsewhere, which added a step for a person at a terminal: trusting the CLI alone would still let any agent with a shell send text as the person, so the person confirms on /dev/tty, and a harness's process gets its run's rules.
11. **An anonymous web form exists, without attachments and with proof of work.** Requiring an account cuts spam, but "anyone submits" would stop being true.
12. **Triage with a hosted model is disclosed, and bodies stay out of factury's git.** The owner chose disclosing over replacing (CO-46, Q-SUP-10; DESIGN-COMPUTE.md §28.13, §28.15): the triage model's provider, Anthropic today, reads the entries triage gives it, as a subprocessor that `support:urnetwork` names with its retention, under an agreement that bars training on them, and triage gives it only entries sent under a `support:urnetwork` version that names it, the version each message's SupportBody carries (§10.1, §12). Committing bodies is simpler but makes retention and deletion promises false.
13. **The sender is "URnetwork support" or "recURd team", with no reply-time promise.** The persona name is the owner's call; the mock's "factury" stays until then.
