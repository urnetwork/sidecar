# Design amendments

Every design decision made since DESIGN.md was last rebuilt and not yet folded into it, ordered by the DESIGN.md section it amends. The decisions were taken in the run's question ledger (`.stack/decisions/LEDGER.json`, ids QD-001 to QD-651), which lives outside git; this file is their durable copy in the sidecar repo.

**Precedence.** Where an item here and DESIGN.md differ, the item governs until it is folded. A complete section of DESIGN-DETAILS.md governs the tasks it names, and where an owner decision below answers one of its questions, the decision governs. Decided items are the owner's; proposed items are the agents' readings and fills, which work builds on until the owner says otherwise.

**Folding.** Only a design-records track edits `design/source/` and rebuilds DESIGN.md with `design/source/build.sh`. Each design-records track takes one DESIGN.md section, applies its items below (and the matching "Proposed DESIGN.md text" of DESIGN-DETAILS.md), and in the same commit deletes those items from this file. When this file holds no items it is deleted. Owner decisions that change behavior go into `design/source/owner/DECISIONS.md` as numbered owner decisions, after decision 197, as decision 197 was.

Holds 169 decided items and 194 proposed ones, generated from the ledger on 2026-11-10. QD-597 (owner decision 197) is already folded, and QD-336 went into §4.5 with owner decision 251 (QD-841 to QD-843), which DESIGN.md carries directly.

## Index

| DESIGN.md section | Decided | Proposed |
|---|---|---|
| [§3 Architecture overview and end-to-end flows](#s3) | 1 | 0 |
| [§5 The Sidecar core](#s5) | 2 | 1 |
| [§7 Networks, teams, members, enrollment, and SSO](#s7) | 4 | 1 |
| [§8 Access control](#s8) | 1 | 0 |
| [§10 Group keys for evs: MLS and the GKM service](#s10) | 1 | 1 |
| [§11 Encrypted versioned storage](#s11) | 1 | 0 |
| [§15 The local email server, inbound mail, and burner email](#s15) | 1 | 0 |
| [§16 The local MCP server and record primitives](#s16) | 6 | 2 |
| [§19 Server services](#s19) | 20 | 21 |
| [§20 Tiers, quotas, metering, and billing](#s20) | 7 | 18 |
| [§21 Abuse, safety, and legal process](#s21) | 17 | 17 |
| [§22 Testing and verification](#s22) | 7 | 15 |
| [§23 Phasing, milestones, and rollout](#s23) | 3 | 3 |
| [No section named](#s0) | 2 | 0 |

## DESIGN-DETAILS.md sections to fold

Sections 2, 4, 5, 6, 8 and 9 of DESIGN-DETAILS.md are complete; each ends with its proposed DESIGN.md text. Their owner questions were answered on 2026-11-10 (QD-598 to QD-629, below under the sections they amend). Three answers differ from a section's recommendation and the design agent amends the section before it is folded: QD-604 (section 8, imports make helper refs), QD-621 (section 4, an overdue narrowing statement keeps the last state and alarms) and the model and wording fixes of QD-628, QD-632, QD-633, QD-642 and QD-644. Sections 1, 3, 7, 10, 11, 12 and 13 are still being written.

Sections 8 and 9's owner answers are folded as owner decisions (2026-11-10): section 9's QD-607 to QD-610, QD-612, QD-632 and QD-633 as 227-233, with QD-613 (section 6's key prefixes) as 234 and QD-640 as 235, and section 8's QD-598 to QD-606 as 236-244, each stated in §11 where it binds. Their proposed DESIGN.md text (8.8, 9.8) waits for the design agent's amendments above, and is folded only with them.

Section 2.8 is folded (2026-11-10): where QD-623 (owner decision 203) needed it with §2's and §3's items, and the rest with §11's, as owner decisions 225 (QD-624) and 226 (QD-625). One part waits: FS-59's checks column, FI-1,6 for FI-6, which sidecartest/fault/catalog.yml must take in the same change, since the fault catalog's test holds each FS row's checks to that file and a design-records track edits no test data; FS-59 keeps FI-6 meanwhile. Of the other sections' §2.8 parts, those their items name are folded: 4.8's (QD-622), 5.8's two settings (QD-629), 6.8's gkm-1 (QD-614), 9.8's evs-11 places (QD-611) and 13.8's (QD-657). Still to fold, with their sections: 5.8's other api-7 words (tail verdicts, open proposals, the applied-id ring, confirmations), which ProjectionHeader.tail_verdicts and ProjectionRows.proposals and ring already carry in protocol/bridge/auth.proto; 8.8's evs-4 words; and 9.8's evs-11 ttl. 6.8's gkm-5 pointers went into §2.8's gkm-5 with §10's items (QD-618, owner decision 363).

<a id="s3"></a>
## §3 Architecture overview and end-to-end flows

### QD-242: Whether a checkpointer's HTTPS POST to a customer's witness may exist, as a new carrier under D-ARCH-2
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

Rule it no URnetwork carrier, in one sentence in §3: a checkpointer's own outbound HTTPS call to a witness a log admin named in a signed, /dev/tty-confirmed `log_settings`. It carries a signed note and a consistency proof, never an entry, no agent can set the host, and §2.8 stands because no URnetwork server takes part. §3.5's map names it as outside the six planes, and RECORD.md section 10.2's step 6 turns on.

Changes: D-ARCH-2; §3.5 planes; RECORD.md section 10.2; Q-RECORD-8.

Questions: `record-md-witness-carrier.md`.

Not folded (2026-11-10): RECORD.md section 10.2's step 6 and Q-RECORD-8, which live in RECORD.md, outside design/source/ and so outside a design-records track's files; the DESIGN.md part is folded as owner decision 214 (D-ARCH-2, §3.5).

Not folded (2026-11-16): the same two parts, still RECORD.md's, which no design-records track edits.

<a id="s5"></a>
## §5 The Sidecar core

### QD-159: How a reader learns and checks an agent subkey
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §6, §11.*

The identity key signs AgentCert{sidecar_id, agent_id, public_key, not_after_ms}, not_after_ms at most 30 days after signing, as a typed Signed with purpose agent-cert and SIGNED_AGENT_CERT = 0x1A02. That Signed rides inside the sealed provenance it vouches for: AgentSignedBody (RECORD.md 5.3) and a push's sealed metadata (§11.6), never a log statement or config record. A reader checks the certificate under the identity key of the sidecar that signed the carrying entry, that the entry's time is before not_after_ms, then the subkey's signature. A bad signature alarms; an absent certificate reads agent_asserted.

Changes: §5.5; §6.9; §6.11; §11.6; RECORD.md 5.3.

Questions: `plan-CORE-agent-revoke.md#1`.

Not folded (2026-11-16): RECORD.md 5.3's AgentSignedBody, which carries the certificate inside a record entry and lives in RECORD.md, outside design/source/ and so outside a design-records track's files; the DESIGN.md parts are folded as text with owner decision 285 (§5.5's agent subkeys bullet, §6.9's purposes, §6.11's SIGNED_AGENT_CERT, §11.6's sealed metadata).

### QD-168: No SidecarEvent kind carries the record's and the directory's reader alarms
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §18, §16.*

Add one kind to §5.4's SidecarEventKind and §18.5's list: `record_alarm`, with a new field `RecordAlarm SidecarRecordAlarm` beside `HeadAlarm`, using the existing `RepoId` and `SidecarId` (the writer or signer). Its closed reasons are 14: chain_gap, chain_fork, bad_entry (RECORD.md section 5.4 steps 1-4, section 5.5 steps 1-3, 5 and 6), depositor_kind, early_removal (a BASE or ERASE taking an entry before keep_days, or a class 7 entry), path_rule, parked_writer, over_cap, over_limit (§16.11's limits row), id_reuse (plan-RECORD-small-readings #2), bad_erasure (an ERASE, CUT or CLOSURE from another signer, or an erasure_request that fails its check), bad_decision, log_check (RECORD.md section 10.2) and moderation, which apps show as a notice. `head_alarm` stays HeadCheck's and `index_mismatch` the index's. plan-EVS1-evs-events' `evs_alarm` stays separate, for storage tampering.

Changes: §5.4 SidecarEventKind and SidecarEvent; §18.5 AddEventListener list; RECORD.md section 18's §5.4 ask.

Questions: `plan-RECORD-alarm-kinds.md`.

Not folded (2026-11-16): RECORD.md section 18's §5.4 ask, which lives in RECORD.md, outside design/source/; the DESIGN.md parts are folded as text (§5.4's record_alarm kind and its RecordAlarm field with the 14 reasons, §18.5's listener comment).

### QD-429: Numbers for the uint32 values inside CanonicalAction, ApprovalRequest and ApprovalDecision
*Proposed fill: a gap the agents filled; work builds on it. Also amends §16, §15.*

RECORD-M2-01 declares four enums in protocol/record.proto; the fields stay uint32 as §16.8 writes them, and 0 is UNSPECIFIED, written by no one. `SidecarActionKind`, in §5.4's order, one verb a value, `restore` appended: 1 publish, 2 listen, 3 forward, 4 expose, 5 egress_change, 6 invite, 7 share, 8 alias_create (burners too, §15.8), 9 alias_delete, 10 agent_config_write, 11 agent_config_delete, 12 dns_set, 13 dns_delete, 14 mail_send, 15 access_request, 16 payment, 17 restore; new kinds append. publish and listen cover tls/ and smtp/ alike, since `host` and `socket_name` say which. `SidecarRisk`: 1 normal, 2 high, numeric order being the max §5.4 takes. `ApprovalVerdict` (`decision`): 1 approve, 2 deny. `ApprovalChannel` (`channel`, and `AclRequestRule.evidence`): 1 device, 2 presence, 3 harness, as RECORD.md section 6.2. `audience` and `app_mode` hold acl.proto's `AclAudience` and `AclAppMode`: a publish's action always writes the resolved non-zero value (members 1, http 1), and a gate maps a request's 0 to 1 before comparing. An approver, spender or gate refuses 0 or an unknown value of any of these; §16.8's "unknown kinds are kept" covers `RecordHeader.kind` only. CORE-M1-01's Go types take these values. Kinds 5, 6, 7 and 16 have no O tool and no row in MCP-M3-02's kind table, so `NewCanonicalAction` refuses each until its owner names its fields. §5.4 and §16.8 record the table at M3's Gn-in.

Changes: §5.4 SidecarAction; §16.8 CanonicalAction, ApprovalRequest, ApprovalDecision; RECORD.md section 6.2.

Questions: `plan-MCP-wire-enum-numbers.md`.

Not folded (2026-11-16): RECORD.md section 6.2's table of the four enums' values, which lives in RECORD.md, outside design/source/; the DESIGN.md parts are folded as text (§5.4's SidecarAction kinds 1 to 17, §16.8's values row).

<a id="s7"></a>
## §7 Networks, teams, members, enrollment, and SSO

### QD-019: Whether per-run cost totals reach the team record, where admins can read a per-person series
*Decided by the owner: owner 2026-11-06.*

per-run totals (tokens by model and reported amounts, never a model_call) go to the team record by default, with Proposed's grouping rules: `ur record cost` groups by project, client or month, never ranks people, and folds groups under 5 members into other. A Team turns it off with ServiceSettings.record_cost, signed by an Owner or Admin, and every member's `ur status` names the setting. This replaces Proposed's off-by-default. (The recommendation it replaces: Per-run totals (tokens by model, reported amounts) go to the team record only in a Team that turns them on: `ServiceSettings.record_cost` (field 8, since `mail_strict` keeps 7, off by default, signed by an Owner or Admin), named in every member's `ur status`. Never a model_call. `ur record cost` groups by project, client or month, never ranks people, and shows groups under 5 members as `other`, which shapes the tool and is no privacy control. Counsel reviews before RS2, and also says whether the default may flip.)

Changes: §7.9 ServiceSettings; RECORD.md sections 6.3 and 13.1; Q-RECORD-6.

Questions: `record-md-run-cost-in-team-record.md`.

Not folded (2026-11-16): RECORD.md sections 6.3 and 13.1 and Q-RECORD-6, which still hold the cost entry in the vault pending that question and live in RECORD.md, outside design/source/ and so outside a design-records track's files; the DESIGN.md part is folded as owner decision 302 (§7.9's settings fields: `record_cost`, field 8, on by default).

### QD-050: Who files the team record's RepoCreate, what refuses a second, and whether a Team may go without one
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §8, §11.*

`team-create`'s first Owner device files RepoCreate{kind team_record} right after the directory's, and an admin device that finds a team whose access logs hold no team_record RepoCreate files it. api and readers refuse a second live one in a network, and api one outside the team tier. Its admins are its creator and every config writer, as the directory's. A RepoDelete of it stands: only a person's /dev/tty-confirmed admin command files a new one, so a Team may decline the ledger and route as personal (RECORD.md section 4.2).

Changes: D-TEAM-28; §7.5; §8.8 RepoCreate row and directory paragraph; §11.12; Q-RECORD-3.

Questions: `record-md-team-record-creation.md`.

Not folded (2026-11-16): Q-RECORD-3, which RECORD.md still lists as open and which no design-records track edits; the DESIGN.md parts are folded as owner decision 303 (§7.5, D-TEAM-28, §8.8's RepoCreate row and team_record paragraph, §11.12).

### QD-062: Tag and group ids name a key that does not exist
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §8, §2, §16, §17.*

[g0-density-keyed-tag-ids] Atom ids are random and table-held, with no key. A tag or group's atom_id is 16 bytes of crypto/rand, drawn by the writer the first time a head names it, redrawn if its first 15 bytes are all zero (acl.proto keeps that form for autogroups), and kept beside its name in the config's sealed `tags` or `groups` file for as long as the name lives. compile reads it from there and refuses a name with no row, so compile stays a pure function of the head. Signed tag_ids stay valid because an id never changes, and a tag deleted and made again gets a new id, so old admissions do not regain it. "keyed HMACs", "keyed ids" and "keyed tag ids" become "opaque ids" in §7.9, §8.7, §8.8, §2.8 api-7, §16.11, §17.8 and Q-ACL-8. This is plan-ACL-atom-and-rule-ids.md#1's answer. [plan-ACL-atom-and-rule-ids#1] Make atom ids random and table-held, with no key. A tag or group's atom_id is 16 bytes of crypto/rand, drawn by the writer the first time a head names it, redrawn if its first 15 bytes are all zero (acl.proto keeps that form for autogroups). It lives beside its name in the sealed `tags` or `groups` file for as long as the name does. compile reads it from there and refuses a name with no row, so compile stays a pure function of the head. Signed tag_ids stay valid because the id never changes, and a tag deleted and made again gets a new id, so old admissions do not regain it. Wording: "keyed HMACs" and "keyed tag ids" become "opaque ids" in §7.9, §8.8, §2.8 api-7, §16.11, §17.8 and Q-ACL-8.

Changes: §7.9; §8.7; §8.8; §2.8 api-7; §16.11; §17.8; Q-ACL-8; §7.9 Writes.

Questions: `g0-density-keyed-tag-ids.md`, `plan-ACL-atom-and-rule-ids.md#1`.

Not folded (2026-11-16): the rewording of api-7's two phrases "member or keyed tag ids" and "keyed tag and group atoms" to opaque ids, which waits on testdata/config/metadata_rows.yml: its `sees` lines quote both phrases, the config rows test holds them to §2.8 word for word, and that file is a code track's. The rest is folded as text: §7.9's Writes says how an id is drawn and kept, api-7 (v29) says in a clause of its own that an atom's id is 16 random bytes derived from no key, and §8.7, §8.8, Q-ACL-8, §16.11 and §17.8 say opaque.

### QD-129: Is ur.io's OAuth consent page in scope, given owner rule 6?
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Recommend in scope: change mmm/ur.io/react/src/components/OauthConsent.jsx on mmm's `sidecar` branch to show the matching code and the one command from `authorization_details`, and add one line to HANDOFF section 5's mmm row. It is the issuer's `authorization_endpoint` and a security control, not product UI.

Changes: HANDOFF section 5; owner rule 6 (its reach).

Questions: `plan-TEAM-consent-page.md`.

Not folded (2026-11-16): the line in HANDOFF section 5's mmm row, since HANDOFF.md is outside design/source/ and so outside a design-records track's files; the decision is folded as owner decision 306, and §7.8's `page` row names the consent page's code and command.

### QD-451: Field numbers of records written as lists
*Proposed fill: a gap the agents filled; work builds on it. Also amends §8, §17.*

Ratify as landed: numbers follow the order the text writes, StatementHeader at field 1. design-records writes them as fenced blocks in §7.9, §8.8 and §17.8, and TEAM-M2-01 and ACL-M2-01 check them line by line.

Changes: §7.9; §8.8; §17.8.

Questions: `protos-bridge-unwritten-numbers.md#1`.

Not folded (2026-11-16): the fenced blocks in §7.9, §8.8 and §17.8. Those records' declarations are held by `testUnfencedFence` in protocol/design_unfenced_test.go, and a ```proto fence for a message listed there fails protocol's fence test until a code track moves the message out of that list in the same change, which a design-records track may not do (it drops only `testFenceAdditions` entries). The rule itself is folded as text: §7.9's record bytes says field numbers follow the order written, with `StatementHeader` at field 1.

<a id="s8"></a>
## §8 Access control

### QD-265: §8.5's grant 1 lost its sidecars when D-ACL-20 narrowed autogroup:untagged
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

§8.5's grant 1 and `acl_team_start.hujson` read { "src": ["autogroup:member", "autogroup:untagged"], "dst": ["autogroup:self"], "allow": ["dial", "route"] }. FS-21's Team case uses peers of two members, since a member's own devices now reach each other.

Changes: §8.5.

Questions: `plan-ACL-team-grant1-src.md`.

Not folded (2026-11-16): line 1 of the worked example's ```hujson block in §8.5. The root package's `TestAclPolicyFixturesAreTheDesigns` holds that block byte for byte to testdata/acl/policy/worked_example.hujson, which is test data and a code track's: fix track team-grant1-via-self moves it with `acl_team_start.hujson`, and the block follows in the same change. The decision is folded as owner decision 344 and stated in §8.5's Grant 1 paragraph, with QD-867's `"via": ["autogroup:self"]`, which amends this item's text.

<a id="s10"></a>
## §10 Group keys for evs: MLS and the GKM service

### QD-046: A forged reader key, beyond correcting the text
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §5.*

[g0-recheck-0-readerkey-forgery#2] Recommended: option 2 on top of the text fix, and no post-quantum signature. Once a day, at its ReaderKey upkeep, a device GETs /gkm/reader-key/<its own id> and compares the key digest with those it signed; a key it never signed raises SidecarEvent key_changed, a kind §5.4 lists and no section yet defines, naming the foreign digest, and the remedy is §10.5's for an active clone: SidecarRevoke{reason: compromise} and a new enrollment. ReaderKey keeps the three fields landed in protocol/gkm.proto. [g0-recheck-0-readerkey-forgery#1] Correct the text, option 1. §10.5's Ladder bullet says an adversary that can forge Ed25519 and that the operator serves "could forge admissions, or a holder's ReaderKey, to which an honest rotator or hinted holder then seals RK_g with no person acting, and, through the ladder, read all retained history". Its last sentence becomes: "An external commit needs RK_g, under which the GroupInfo is sealed, so a published identity key alone commits nothing; RK_g itself rests on those signatures." §2.18's unaudited-cryptography row adds "by a forged admission or ReaderKey", and the ledger's HNDL row replaces "Nothing" with this residual. Q-KEYS-2's residual stands.

Changes: §10.5 Ladder bullet; §2.18 unaudited-cryptography row; ledger row for R3's HNDL major; §10.5 readerkey row; §5.4 key_changed; §10.15 active clone row.

Questions: `g0-recheck-0-readerkey-forgery.md#1`, `g0-recheck-0-readerkey-forgery.md#2`.

Not folded (2026-11-16): the ledger's row for R3's HNDL major, whose "Nothing" becomes this residual, since that row is in DESIGN-REVIEW-RESPONSE.md, outside design/source/ and so outside a design-records track's files; the DESIGN.md parts are folded as owner decision 358 (§10.5's Ladder and readerkey rows, §10.15's active clone row, §5.4's `key_changed`, §2.18's unaudited-cryptography row).

### QD-471: Numbers for GroupForm, which only §2.8's gkm-1 lists
*Proposed fill: a gap the agents filled; work builds on it. Also amends §2.*

As landed: GroupForm{repo_id = 1, group_id = 2, previous_group_id = 3, generation = 4}, its signer being Signed's, and design-records adds the fence to §10.6. These are numbers only: what a re-form checks, and any field that adds, is plan-KEYS-reform-ladder's.

Changes: §10.6.

Questions: `protos-services-unwritten-numbers.md#3`.

Not folded (2026-11-16): the ```proto fence for GroupForm in §10.6. GroupForm's declaration is held by `testUnfencedFence` in protocol/design_unfenced_test.go, and a fence for a message listed there fails protocol's fence test until a code track moves the message out of that list in the same change, which a design-records track may not do; the numbers are folded as text, with QD-643's `auth = 5` (owner decision 368), in §10.6's bodies block.

<a id="s11"></a>
## §11 Encrypted versioned storage

### QD-176: A depositor cannot see a CONSUME, so D-MCP-10's "spool until consumed" has no mechanism
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §16.*

The ingester declares a mark in its CONSUME: `EvsPush.consumed_through` (uint64, field 35), the highest version of this deposit ref at or below which no unconsumed deposit remains, by its own read. evs copies it to `EvsHead.consumed_through` (field 27), never falling, and returns it beside {v+1} in a deposit push's 200 and in plan-EVS1-deposit-head's refusal body. The depositor stores each spooled deposit's push version and prunes at or below the mark; everything else stays within §16.7's 1 GiB, oldest dropped first, coverage naming spool_drop. No age bound: ingest lets no outcome hold a ref back (RECORD.md section 5.4), so the mark does not stick, and 30 days would drop exactly an offline author's deposits. §2.8 evs-3 gains the field and says a depositor, receipt-only readers included, learns when its deposits were ingested.

Changes: §11.6 EvsPush; §11.8 EvsHead and the 200 reply; §2.8 evs-3; §16.8 Mirrors and site loss; RECORD.md sections 5.4 and 5.7.

Questions: `plan-RECORD-depositor-spool.md`.

Not folded (2026-11-16): RECORD.md sections 5.4 and 5.7's part, the depositor spool's pruning at the mark, which lives in RECORD.md, outside design/source/ and so outside a design-records track's files; the DESIGN.md parts are folded as text (§11.6's EvsPush and §11.8's EvsHead fences take consumed_through, §11.12's deposits paragraph, §11.8's step 8 and 5f, §2.8's evs-3 and evs-12, and §16.8's mirrors bullet).

<a id="s15"></a>
## §15 The local email server, inbound mail, and burner email

### QD-025: Whether tracks may fetch mail modules through the Go module proxy
*Decided by the owner: owner 2026-11-08.*

Option 1: tracks fetch the Go modules the plan names through proxy.golang.org, checked against go.sum and the checksum database; each gets its dependencies.yml row with the license read from its files.

Changes: BRIEF.md tlc bullet.

Questions: `mail-m5-02-module-fetch.md`.

Not folded (2026-11-16): it changes only the run's brief, which carries it (BRIEF.md's paragraph of 2026-11-08 on Go modules through the module proxy); DESIGN.md sets no rule for what a build track fetches, and §4's Go line already takes the toolchain through the module proxy, checked against Go's checksum database (owner decision 272).

<a id="s16"></a>
## §16 The local MCP server and record primitives

### QD-018: A forged SessionStart can leave a tainted run behind
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §5.*

Recommended: option 1, with its limit stated. The run file keeps the harness process's identity (pid and start time; local, never shown). Every session or event under a harness process binds to the union of that process's runs, ended ones included: a new run there starts with their taint, fsynced, until the process exits. Only a SessionStart reporting a fresh start opens a new run, a session with no live harness ancestor binds nothing and reads tainted, and SessionEnd clears nothing. §16.6's monotone row reads "a new run starts untainted unless a run of its harness process is tainted". FS-27 gains forged SessionStart and SessionEnd steps. §2.10 and §16.17 state the residual: a process that leaves the harness's tree (setsid, a launchd or systemd job, a second harness started detached) inherits nothing and can use what §5.5 leaves to any local process, so I-9 binds runs, not all of a user's processes (owner decision 47).

Changes: D-MCP-16; §16.6 monotone; §16.6 run file; §16.6 rejoin; FS-27; §2.10 P0 row; §16.17; RECORD.md section 4.3.

Questions: `plan-MCP-taint-new-session.md`.

Not folded (2026-11-16): RECORD.md section 4.3's part, the union of a harness process's runs for a run's binding, which lives in RECORD.md, outside design/source/ and so outside a design-records track's files; the DESIGN.md parts are folded as owner decision 448 (§16.6's run file, rejoin and monotone rows, D-MCP-16, §16.17, §2.10's P0 row and FS-27).

### QD-127: What P5:728's "a person approved a change" is, when approvals bind only outward actions
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

An `attestation` entry (kind 29, RECORD.md section 11): a person's signed statement (1 reviewed, 2 tested, 3 approved) about named commits, by `ur record attest` on /dev/tty or in an app's UI, with an SSHSIG where the member holds a key. It sits outside the I-8 gate, is never called an approval, and P5:728's copy says what it is.

Changes: RECORD.md sections 6.3, 11 and 17; Q-RECORD-7; P5:728 copy.

Questions: `record-md-change-approval.md`.

Not folded (2026-11-16): RECORD.md sections 6.3, 11 and 17 and Q-RECORD-7, which RECORD.md still marks pending, and P5:728's copy in sidecar/design/pitch5.html, all outside design/source/; the DESIGN.md part is folded as owner decision 453 (§16.8's approvals bullet).

### QD-138: Nothing in the design writes a `record` repo's entries
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

A log admin's `ledger_scope` entry (kind 43, RECORD.md section 6.5) names the repos and projects a ledger covers, and a sidecar with write on that log adds a copy of each T-bound run entry: T's projection, never a vault body. No tool changes and no agent chooses a log. `ur status` names each `record` log a daemon copies to, so a member can see it.

Changes: RECORD.md sections 6.3 and 6.5; §16.8 matrix; Q-RECORD-4.

Questions: `record-md-record-repo-writers.md`.

Not folded (2026-11-16): RECORD.md sections 6.3 and 6.5 and Q-RECORD-4, which RECORD.md still marks pending, outside design/source/; the DESIGN.md part is folded as owner decision 454 (§16.8's logs table).

### QD-203: §16.8's total order for a log cannot span its streams
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

§16.8's order row becomes: within one stream, (evs push version, position in the push), each push's entries sorted by (writer, seq); across a log's streams the verifiable log appends in batches, batch by batch, streams by ref_id bytes within a batch, each checkpoint entry listing its frontier and leaves; no log-wide sequence, no format change. RECORD.md section 10.1 stands as drafted. Land this before M3's Gn-in, not M6's entry as the question says, because D-MCP-6 freezes log order with the envelope.

Changes: §16.8 order row; D-MCP-6; Q-RECORD-1.

Questions: `record-md-log-order-across-streams.md`.

Not folded (2026-11-16): Q-RECORD-1, which RECORD.md still lists as open, outside design/source/; the DESIGN.md parts are folded as text (§16.8's order row and D-MCP-6).

### QD-261: evidence_sha256 cannot hold the WebAuthn assertion that signs it
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

§16.8's comment becomes: harness: the matched hook event, which stays in the record; device and presence: empty, a presence decision's assertion riding in Signed.webauthn. Writers leave field 10 empty on channels 1 and 2. RECORD.md section 5.1 stands, and protocol/record.proto's copy of the comment follows.

Changes: §16.8 ApprovalDecision comment; protocol/record.proto comment; Q-RECORD-2.

Questions: `record-md-presence-evidence-sha256.md`.

Not folded (2026-11-16): Q-RECORD-2, which RECORD.md still lists as open, outside design/source/; the DESIGN.md part is folded as text (§16.8's ApprovalDecision comment), and protocol/record.proto's comment already reads so.

### QD-651: What bytes does `ur record open` write, and does a packet's `--content` take them?
*Decided by the owner on 2026-11-10, asked one question at a time.*

The file ur record open writes, and ur record disclose --content reads, is a new record.proto message, DisclosureOpenings {version, log_id, repeated Opening openings, repeated DisclosedKey keys, purpose}, which cannot be mistaken for a DisclosurePacket; the vault's disclosure entry of act 2 records its SHA-256 as packet_sha256. Adopted at M6's entry review: RECORD-M6-06's Open writes it and Disclose reads it (two functions), with a section 20 vector. RECORD.md section 11 names the message (design-records or RECORD's own doc).

Changes: RECORD follow-up at M6 entry review: DisclosureOpenings in record.proto, Open and Disclose, a vector; RECORD.md section 11 text.

Questions: `record-m6-05-open-file-format.md`.

Not folded (2026-11-16): RECORD.md section 11's text naming the message, outside design/source/; the DESIGN.md part is folded as owner decision 456 (§16.8's disclosure row), and DisclosureOpenings itself waits on record.proto (RECORD-M6-06).

### QD-360: The requester's record of an outcome is a `copy` entry
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The requester writes a `copy` entry (kind 39) to the member's vault, CopyBody holding one Opening (header, salt, body) per decision entry the notice names; a tagged requester deposits it to its sponsor's vault and writes none while it has no sponsor. RECORD.md's CopyBody comment and row 39's writer widen from "deposited to T" to cover it. As with every copy, an erasure of the decision in the directory does not reach it, and its prose stays a stub for agents.

Changes: RECORD.md sections 6.3 and 6.4.

Questions: `plan-RECORD-small-readings.md#6`.

Not folded (2026-11-16): RECORD.md sections 6.3 and 6.4, CopyBody's comment and row 39's writer, outside design/source/; the DESIGN.md part is folded as text (§16.11's receipt row).

### QD-581: Product copy may not keep "per request" for model receipts
*Settled by the agents from the design; work builds on it.*

No. Per-request signing stays out of scope, and copy follows. At RS2 P5:779 says per grant and 5-minute window, with calls recorded per request from the harness at hook strength, and P5:766's "can prove" takes RECORD.md section 12's evidence labels. RECORD.md sections 12 and 17 stand, and no code changes.

Changes: P5:779 and P5:766 copy.

Questions: `record-md-model-receipt-granularity.md`.

Not folded (2026-11-16): P5:779's and P5:766's copy in sidecar/design/pitch5.html, outside design/source/; DESIGN.md already says it, D-CTX-5 keeping per-request signing out of scope.

<a id="s19"></a>
## §19 Server services

### QD-021: M2 code names networks by label, but dns_label arrives with MG5
*Decided by the owner: owner 2026-11-06. Also amends §12, §23, §7, §9.*

follow Proposed as the rule (dns_label moves to MG2). (The recommendation it replaces: Move dns_label alone from MG5 to MG2, pending until M2's Gn-out, with model.EnsureNetworkLabelInTx, model.ResolveNetworkLabel and lazy allocation. The rest of dns_* and all DNS serving stay M5; aliases stay M6. Add GET /sidecar/label on api (Client class, sidecar-classified, so §7.4's /sidecar/* covers it): it answers {network_id, label, alias}, allocating on first need, and feeds DNS-M2-01's table. From M5 GET /dns/zone answers the same values. Draws before M5 run ValidateDnsName's reserved and brand rules from DNS-M0-01, which hold §12.5's list, curated brands included; ScreenName joins at M5 for later draws. <net> in .ur, git-remote-ur, §9.4 addresses and network:<net> then holds a real label from M2.)

Changes: §19.7 MG2 and MG5; §12.14; §12.16; §23.4 M2.

Questions: `plan-DNS-labels-before-m5.md`.

### QD-022: Who owns tls/current on an lb host, given that the vault copy writes through links and can destroy a JWT key
*Decided by the owner: owner 2026-11-06.*

stay on versioned paths for now. Nothing changes in production: no vault entry or lb image reads tls/current, W5's swap stays built but unused, and OPS-M5-07 builds against a test vault. This replaces Proposed. (The recommendation it replaces: Keep tls/current out of the vault entirely; hosts own the links. A new services.yml list, lb.tls_current: [<name>...], tells warpctl lb create-config which names read tls/current/<name>, and every other name keeps its newest versioned path, so the fallback per name stays. The builder refuses a vault that holds tls/current, so the write-through cannot start. warpctl certs swap <env> <version> moves the links on each lb host and reloads. It must also run with no lb up, to seed a new host or roll back, and must fail, not print Reloaded, when a running lb's config does not read tls/current or a listed name is missing from the version (the track review's two majors). playbook-edges.yml runs the swap right after its vault copy, so renewal stays one vault deploy, and xops/certs/renew.md gains that step. TLS-M6-01's lbmap keeps its own in-container reload.)

Changes: §19.5 W5; D-OPS-12; §19.11.

Questions: `warp-w5w6-tls-current-delivery.md`.

### QD-029: How exposed edge services reach data
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §13, §2, §12.*

[plan-TLS-edge-data-source] tlsedge reads Postgres, as §13.9 and tls-3 already have it. Its secret_files gain redis and a restricted Postgres role in its own vault file: SELECT on dns_label, network_dns_custom_host, network_tls_suspension and §12.9's suspensions, INSERT on tls_connection_record, nothing else. TlsEdgeStore is a background loop: a full snapshot at start, then model.DnsLabelMapSince every 5 s, so a withdrawn name stops mapping within 10 s. Kills still arrive within 5 s through {tes_} and reload every 60 s (§13.9). Records go in 10 s batches off the path. In a Postgres outage running processes keep their last snapshot, but a process started then stays not ready, so §19.10's 'edges run from Redis' reads 'run from memory and Redis; a restart waits for Postgres'. No connection path touches Postgres (I-12). [mx-foundation-router-store] Follow plan-TLS-edge-data-source, so the two edges match. Under its recommendation the router block gets a scoped Postgres role, used only from batch goroutines (I-12), and OPS-M7-01's "a router block takes no Postgres pool" is corrected, as plan-SMTP-report-intake-home also says. Separately, MAIL-M5-03 marks the platform role as needing no `MxEdgeStore`, so `Ready` waives it: it has no rows to write, and a stand-in store would prove nothing.

Changes: §19.4; §19.10; §13.5; §2.8 tls-1; §19.4; OPS-M7-01; MAIL-M5-03.

Questions: `plan-TLS-edge-data-source.md`, `mx-foundation-router-store.md`.

### QD-035: How the file cluster shows degraded-write debt, and how a set leaves `degraded` after a partial write
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Recommended, with one correction to the question: its option 1 is not available without a patch, because the admin API shows no partial-write queue at all. In the minio fork: er.addPartial sets SetIndex and PoolIndex (today it leaves them zero), and cmd/mrf.go exports, per pool and set, queue depth, a count of dropped entries and a count of unclean starts, since a crash loses the queue (only shutdown() saves it). monitor exports them as urnetwork_filecluster_mrf_depth{cluster,set}, urnetwork_filecluster_mrf_dropped_total{cluster,set} and urnetwork_filecluster_unclean_starts_total{cluster,set}. §19.6: `degraded` is entered on a drive or host offline or a depth above 0. It is left when a full heal ends with every drive online, or, if no drive or host was offline, when depth reaches 0 with no drop or unclean start since the last full heal. A drop or unclean start with every drive online raises a warn and starts one full heal. FS-40's DriveMiss phase holds healing, asserts `degraded` and depth 1 before nodes C and D go down, and adds a planted drop. Ledger S11's "Nothing" points at this row.

Changes: §19.6; §19.8; §19.10; FS-40; D-OPS-14; D-OPS-20.

Questions: `g0-recheck-1-s11-degraded-write-debt.md`.

### QD-040: How sockets authenticates a Client-class caller and learns its §8 subject with no Postgres and no by_jwt keys
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §5, §2, §9, §8.*

Keep Client class. Verify: sockets mounts a public-key export of the by_jwt keyring in `secret_files`, and session gains a verify-only keyring that rereads it as `byJwtKeyring` does. State: a new no-SQL check reads the revocation record alone: valid passes, a tombstone or rotation answers 401, Redis failure answers `unavailable`, and a miss answers `unavailable` with `retry_after_ms`, never SQL. A token with no root claim is refused. Grace: `{sc_<client_id>}ok` holds the last valid time, and a miss within 120 s of it counts as valid without moving it; a revocation in that span shows as a tombstone, which lives 10 min. This is needed because a client's positive field expires in 54-60 min and only a later check re-projects it, so connect's 60 s recheck leaves a gap of up to 60 s that would outlast a 45 s lease; the question's 'stays warm' is wrong there. Subject: `by_client_jwt` gains a `sidecar_id` claim; `POST /sidecar/bind`'s 200 adds a re-minted `by_client_jwt` beside `generation`, and refresh keeps the claim; a token without it is `denied` unless its network is `urnetwork-edge`. `revocation_record_enabled` must be on in production before M5. §19.10 and §19.17 then say sockets runs through about an hour of Postgres loss, since fields lapse and cannot be re-projected, after which it answers `unavailable`. sock-2 gains the sidecar id.

Changes: §19.4 sockets row; §19.10; §19.17; §5.15 bind reply; §2.8 sock-2; §9.8 {sc_}.

Questions: `plan-SOCK-client-auth.md`.

### QD-056: Nothing records that a cluster's running build passed FS-114, or its measured HDD capacity
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §22.*

Option 1. Add to config/<env>/sidecar.yml: file_clusters: {<cluster id>: {settle_passed_build: <commit>, hdd_capacity_ops: <n>}}, reread every 60 s as the file is. BlobCluster.SettlePassed is true only while every host's build in admin info equals settle_passed_build. An absent entry, an unreadable admin info or any mismatch reads false, so an upgrade reads false until the operator records the new build after filecluster-suite passes, and meanwhile no collection window opens and purges and drops delete nothing. hdd_capacity_ops is what §22.8's M3 hdd run measured, and {nvb_<cluster>} publishes it; while it is absent evs refuses no upload on HDD grounds and a drop job stays paused. Reword §19.6's settle and hdd rows and §19.11's yaml.

Changes: §19.11 sidecar.yml; §19.6 settle and hdd rows.

Questions: `plan-EVSB-settle-gate.md`.

### QD-076: What keeps api's public routes, the token exchange and CreateContract closed until §19.10's api step ends?
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Add `restore_hold: false` to §19.11's `sidecar.yml`. While it reads true, api answers every public route but its status route 503 with Retry-After 60, the token exchange answers the same, and connect's CreateContract answers `ContractError.Setup`. Open streams, sockets and edges are untouched, and §19.10's dns and api steps run as jobs behind the hold. The restore runbook's first step sets it, before the primary answers; the end of the api step clears it. A reader that cannot read the file keeps its last answer. FS-42 checks that a client revoked between the dumps gets no token or contract while it holds.

Changes: §19.10; §19.11; D-OPS-10; FS-42.

Questions: `plan-OPS-restore-hold.md`.

### QD-084: §19.9 narrows P0 against §11.13, D-EVS-33 and §7.9, and hold/, place/ and repo creation have no class
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §11, §7.*

Option 1. rev/, proj/ and projrows/ writes are all P0, kinds revocation and log. hold/ is P0, kind lifecycle. place/, a repo's creation writes (repo/, its first head) and activate's CAS are P1, queued per network by evs. Per-sidecar gkm/ stays P1. Reword §19.9's first row: 'their rev/, proj/, projrows/ and hold/ writes are §11.13's P0 and the rest queue per network'. Add projrows/ and hold/ to §11.13's classes row and D-EVS-33's list. api then needs no queue and only reports P0 bytes, as §7.9 says.

Changes: §19.9 first row; §11.13 classes row; D-EVS-33.

Questions: `plan-EVSB-write-classes.md`.

### QD-151: M5's report intake has no process or tables, since smtpedge and MG9 arrive at M9
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §14, §4, §15.*

Option 1. `SmtpReportIntake` runs in-process in the `mxedge-platform` block, as a library from `smtpedgeservice`, which server may import (§4.4). `smtp_complaint` and `smtp_dmarc_daily` move to MG5, and the rest of `smtp_*` stays in MG9. mxedge-platform takes a Postgres pool of 2 (§19.7's default). OPS-M7-01's 'a router block takes no Postgres pool' is a plan error to fix alongside: §15.4's 10 s `mail_connection_record` batches and §19.4's state column need one, off the connection path. Attribution and halts stay at M9 in the same package, once `smtp_send` exists. smtp-5's service reads 'mxedge (platform listener), then smtpedge'.

Changes: §19.7; §19.4; §2.8 smtp-5; §14.9; §14.14; D-SMTP-11.

Questions: `plan-SMTP-report-intake-home.md`.

### QD-163: warp cannot deploy one dnsedge service one host at a time
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §12.*

Two warp services, dnsedge-1 and dnsedge-2, each with one hosts: entry (ns1, ns2), one block, the same external_udp_ports and W9 TCP 53, and one image: server/cli/dnsedge builds it once and build/all/run.sh runs warpctl import <env> <image> --service_name=dnsedge-1 and -2, as it already does for manager to app (run.sh:3554). deploy-rollout.zsh lists both as single pass, dnsedge-1 first, and applies Q-OPS-5's stop rule (canary signature clean, NS serials equal) before dnsedge-2. dnsedge stays the role's name in §12 and the class name in §19.11. warp's core does not change.

Changes: §19.4 dns row; §19.11 Classes.

Questions: `warp-w5w6-dnsedge-one-host.md`.

### QD-182: §19.9's hdd trigger cannot be evaluated: no named series, no alert, unlike units
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §22, §23.*

Add to §19.8, published by §19.6's hdd loop, which already reads the counters, with no network or repo label: urnetwork_filecluster_hdd_drive_ops{cluster} and urnetwork_filecluster_hdd_capacity{cluster}, in drive operations a second, and urnetwork_filecluster_hdd_puts{cluster}, segment PUTs a second. Add resources hdd_ops and hdd_puts to urnetwork_filecluster_exhaustion_days{cluster,resource}. §19.9's trigger reads: the placement and the added capacity are ordered when monitor's 30-day trend of hdd_ops projects 50% of measured capacity, or its 30-day trend of hdd_puts projects §22.8's admitted throughput, within their lead time (§23.7), and land before it. §19.8's business row adds: a segment cluster whose projected hdd_ops or hdd_puts crossing falls within that lead time pages in business hours.

Changes: §19.8 metrics and business row; §19.9 hdd row; D-OPS-17.

Questions: `g0-recheck-0-hdd-trigger.md#1`.

### QD-214: FS-41 and FI-5 expect the close report to name an erasure §19.10 says it cannot
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §11.*

FI-5 and FS-41 follow §19.10's close row: the report names a repo that came back only under an EvsReseed as one where a lost ERASE may have returned keys, and never names the erasure. FI-5 reads "unless no surviving device holds the ERASE (§11.12's residual), which §19.10's close report flags by repo". FS-41 reads "with only stale mirrors, a repo that came back under an EvsReseed is flagged; with no reader pin above the mirror nothing names it, the stated residual".

Changes: FI-5; FS-41.

Questions: `g0-recheck-2-reseed-slot-keys.md#2`.

### QD-234: Which pager service does the rota use, and who owns the 30-minute escalation?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §23.*

A commercial pager service owns rotas, acknowledgment and the 30-minute escalation, reached from outside the site; the owner picks the vendor. `monitor` posts events with a dedup key through `pager.Sink`, a generic HTTPS event client, and page bodies hold class, time and opaque ids only, never a network name, address or token. A fake sink models the policy for FS-50 at T3, and the real policy is proved on the out-of-hours drill. §2.8 gains an ext row before it goes live (I-18).

Changes: §19.8; §2.8 ext rows; §23.7.

Questions: `plan-OPS-pager-service.md`.

### QD-236: Is there a canary environment to build for?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §22, §23.*

Build the cheap parts now: OPS-M2-05's `sidecar_pending` tag leg, a `config/canary/` a host could use, and `canary` kept in `sidecarPendingAllowed`. No plan counts a canary deploy as evidence, since T3 and M2's staging cluster prove stores and hosts. End state: drop the tier from §19.7, §19.11, §22.4 and §23.8 unless the owner buys hosts for it.

Changes: §19.7; §19.11; §22.4; §23.8; D-OPS-6; D-OPS-10.

Questions: `plan-OPS-canary-env.md`.

### QD-248: idx/ entries carry their state in object metadata, and only §19.6's MinIO row says otherwise
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §11.*

Option 1. Keep §11.6, §11.7, §11.8, §11.13 and evs-11. Reword §19.6's MinIO row to: objects carry content-type application/octet-stream and no user metadata, except an idx/ entry's state while its head lists sources (§11.7). The key is entry-state, the name blobsuite already uses, and its value is carried:<source epoch in decimal>, fresh or removed, read by HEAD; every other family carries none. A prefix check stays a HEAD, and no format changes.

Changes: §19.6 MinIO row.

Questions: `plan-EVS1-entry-state-metadata.md`.

### QD-249: §19.4's `secret_files` omit the metrics push credential every block needs
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

§19.4 gains one push-only vault file per service, `grafana-push-<service>.yml`, holding one user with the push role, in each new block's `secret_files`. `grafanaPushSettings` reads it first, then vault's `grafana.yml` for existing services. Never mount `grafana.yml` on a new block. Per service rather than the question's one shared file, so one compromised hostile-facing block's credential is revoked and rotated alone.

Changes: §19.4.

Questions: `plan-OPS-small-readings.md#5`.

### QD-252: §19.9's gen trigger has no input series
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §22.*

Add urnetwork_filecluster_gen_objects{cluster} to §19.8: a gauge EVSB-M2-12's nightly pass sets from its gen/ count, with no group or repo label, kept in monitor's 30-day trend beside the cluster's objects, and add resource gen_objects to urnetwork_filecluster_exhaustion_days{cluster,resource}, as g0-recheck-0-hdd-trigger.md#1 does for hdd. §19.9's gen row then reads: a warn when that trend projects gen/ past 10% of the cluster's objects within the next metadata cluster's lead time. §22.8's M2 count seeds the projection. The lead time's value follows g0-recheck-0-hdd-trigger's answer.

Changes: §19.8; §19.9.

Questions: `g0-recheck-2-gen-pack-trigger.md#1`.

### QD-260: A pack PUT must ride the streamed path, with an overall cap the question missed
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §11.*

Option 1, with a bound. pack/ PUTs are streamed PUTs: PutStream with the pack's SHA-256, no x-ur-deadline-ms, settle rule (2)'s 40 s after the last byte. taskworker cancels one whose last byte has not gone 8 min after issue, and the next run retries the pack. 5 s of cached repo/, 8 min and 40 s stay inside §11.12's 10 min phase 6. One pack per repo a run stands. Reword §19.6's deadline and settle rows, D-OPS-20 ('every request but a streamed segment or pack PUT'), §11.13's needs row and host_blobs.go's PutStream comment.

Changes: §19.6 deadline and settle rows; D-OPS-20; §11.13 needs row.

Questions: `plan-EVSB-pack-put.md`.

### QD-279: §19.6 and D-OPS-20 place a DELETE's copy in .trash, which a restart wipes
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Change "a DELETE's .trash copy" to "a DELETE's stash" in §19.6's settle rows and EVSB-M2-18's summary, with the sweep rule as built: the copy lives in `.minio.sys/settle`, which nothing wipes, and its sweep keeps it past a minimum age while any lock server or local write holds the key.

Changes: §19.6 settle rows (3), (4); D-OPS-20.

Questions: `minio-settle-stash-not-trash.md`.

### QD-639: Where does an evs process learn how many evs blocks serve, so evs_unpaid_read_rate divides by it?
*Decided by the owner on 2026-11-10, asked one question at a time. Also amends §13.*

evs takes a blocks count from config, as tlsedge does (§13.9, TLS reading 12): a key in config/<env>/sidecar.yml's evs gate block (or an evs settings file), set by the operator with services.yml's evs block count, which server/evshost passes as QuotaGateSettings.Read.Blocks. The read path keeps no shared state. The two built readings stand: a non-positive limit reads as unpaced, and FallbackRate (1 MiB/s split by blocks) paces until limits are read. An ops-lane follow-up wires it; §19.4's evs row names the key (design-records).

Changes: ops follow-up: evs blocks key in config/<env>/sidecar.yml and server/evshost passing it; §19.4 evs row (design-records).

Questions: `quota-m2-10-evs-block-count.md`.

### QD-285: W6's M0 deliverable is the recipe, and each service's task lands its own six artifacts
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

W6 at M0 means warp's README 'Adding a service' and warpctl/service_blocks_test.go. Each service's own task lands its Makefile, Dockerfile, lock entry, source graph, run.sh lines and rollout class at that service's milestone. A service joins staged_services only in the milestone its block lands (plan-OPS reading 12), since warpctl deploy panics with 'No matching blocks.' on a service with no blocks. Reword §19.11's Order step 1 to 'W6's recipe' at the next records pass. The README's steps 6 and 7 should also name build/all/deploy_rollout_test.go:204 and build/all/test_release_preflight.py:20, as the track review found.

Questions: `warp-w5w6-w6-ownership.md`.

### QD-297: §19.7 names RunRedisShardSubscription for the hint listener
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §6.*

§6.8 wins: publishers run on the exchange's shared keyEventSubscriber, whose SubscribeKeyEvents follows the master set. Replace §19.7's sentence (19-OPS.md:415) with "The hint listener rides §6.8's keyEventSubscriber, which re-reads the master set".

Changes: §19.7.

Questions: `plan-PROTO-small-readings.md#2`.

### QD-302: Per-block cluster credentials
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`file-clusters-<service>.yml` per block, read by EVSB-M2-02's `LoadFileClusters` in place of its one `file-clusters.yml`, each holding that block's MinIO user and policy.

Questions: `plan-OPS-small-readings.md#7`.

### QD-308: `{vault: no}` and `server.Vault`
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Every new block sets `env_vars: {WARP_VAULT_HOME: /srv/warp/secrets}`, so `Vault.RequireSimpleResource("redis.yml")` works unchanged, and Ansible makes each mounted file 65532:65532 mode 0400, as playbook-edges.yml does for grafana.yml.

Questions: `plan-OPS-small-readings.md#4`.

### QD-312: `ServiceHost.Tasks` outside taskworker
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`Tasks` is nil in evs and gkm processes, whose jobs run in taskworker and reschedule themselves. An engine that needs a job from a request path raises it as a question. KEYS-M2-17's `Tasks` holds only for the reconciler's registration in taskworker. host_tasks.go's "From any process" narrows to processes with Postgres.

Questions: `plan-OPS-small-readings.md#8`.

### QD-325: Readiness on a block with no Postgres
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`sidecarhost.Run` latches on `Engine.Ready()`; a block with Postgres also runs the shared check and its groups' markers.

Questions: `plan-OPS-small-readings.md#9`.

### QD-357: D-OPS-16's filter
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Load each dump into a scratch `redis-server` of the pinned version, delete the families, save, then compress, one node at a time, publishing nothing on any failure.

Questions: `plan-OPS-small-readings.md#13`.

### QD-362: The rollout stop
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A burn state monitor cannot read stops the step too, and an operator overrides by name.

Questions: `plan-OPS-small-readings.md#11`.

### QD-368: `cap_net_admin` for smtpedge
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Extend both allowlists, warp/services/load.go:167 and warp/warpctl/run.go:159, to smtpedge only, and set the capability on the binary in the image, so it still runs as 65532.

Questions: `plan-OPS-small-readings.md#14`.

### QD-371: The staged list grows
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Classes land at once, and each service joins `staged_services` in the milestone its block lands.

Questions: `plan-OPS-small-readings.md#12`.

### QD-380: W8's log shape
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`$request` becomes `"$request_method $uri $server_protocol"` by host, so each line keeps its three fields inside the quotes; hosts without sidecar routes keep `$request`.

Questions: `plan-OPS-small-readings.md#10`.

### QD-400: Front matter says `gen/` stays unpacked, where §19.14 gives it gen packs
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §10.*

§19.14 and §10.16 hold: gkm's gen/ takes gen packs at §19.9's gen trigger. Replace "`gen/` stays unpacked" at asm/data_front6.py:163 with "`gen/` takes §10.16's gen packs at §19.9's trigger", fix the comment at :144, and rebuild DESIGN.md.

Changes: front matter Q-OPS-2 row.

Questions: `g0-recheck-1-closed-item-text-errors.md#5`.

### QD-407: Whether rule (2)'s "metadata rename" reaches tagging, retention and self-copy
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Read "metadata rename" in §19.6's settle row (2) as RenameData with inline data, and say so in that row. UpdateMetadata and WriteMetadata carry no version and are not settled. They run under the key's write lock, take the clock rule and a 40 s deadline, and no sidecar service calls them.

Changes: §19.6 settle row (2).

Questions: `minio-settle-metadata-commits.md`.

### QD-411: Q-OPS-3's residual is closed in §19.14 and open in the front matter
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §23.*

It is closed: §19.14 owns Q-OPS-3 and reads "Residual: none", and §23.6's M0 row keeps D-OPS-18's closure as a gate. Drop the Q-OPS-3 clause from PEER_INTRO (asm/data_front7.py:123-125), leaving one residual. Add "Q-OPS-3's residual" to the ledger's section 5 beside Q-QUOTA-3's, keeping Appendix B's status as decided by the owner. Copy §19.6's bound into Q-OPS-3: <= 24 h plus the run (<= 20 min) at a primary's loss, <= 26 h at the site's, a day more per skipped or aborted run; and say "the dumped sidecar rows", since tables with a ttl of at most 7 d are in no dump. The "Closed by peer review 2026-11-04" label stays, as OT-N7's own row records that marking.

Changes: front matter PEER_INTRO; ledger section 5; Q-OPS-3 text.

Questions: `g0-recheck-2-q-ops-3-records.md`.

### QD-414: Three copies say "50% of rated IOPS" where §11.13 says rated write IOPS
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §22, §11.*

The limit is 50% of rated write IOPS (85k on the PM9A3), per §11.13 (11-EVS.md:1675), R-EVS-19 and D-EVS-33. Insert "write" at R-OPS-12 (19-OPS.md:22), 22-TEST.md:659, R-PHASE-11 (23-PHASE.md:21) and 19-OPS.md:279, a fourth copy the question missed.

Changes: R-OPS-12; R-PHASE-11; §19.6; §22.8.

Questions: `g0-density-text-alignments.md#5`.

### QD-421: Does `network_acl_share` join it?
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §2.*

[xops-dump-short-ttl-list#2] Yes. No dump holds it. An open invite is lost at a Postgres restore and is issued again. design-records adds its name to §19.6's list. [plan-DNS-metadata-rows#9] No decision needed. dns_label stays in api-2, where §2.8 has it. dns_custom_host_map stays out of every dump by §19.6's rule; add its name to the rule's 'today' parenthetical at the next records pass. [xops-dump-short-ttl-list#1] Yes. No dump holds it, as sidecar-tables.conf already marks. design-records adds its name to §19.6's list.

Changes: §19.6.

Questions: `plan-DNS-metadata-rows.md#9`, `xops-dump-short-ttl-list.md#1`, `xops-dump-short-ttl-list.md#2`.

### QD-458: taskworker reads each storage host's drive counters from a 5 s fluent-bit exporter on the storage LAN
*Proposed fill: a gap the agents filled; work builds on it.*

Option 1. On each storage host, a second fluent-bit pipeline beside the 15 s remote-write one: input node_exporter_metrics, scrape_interval 5, metrics diskstats; output prometheus_exporter on the host's storage-LAN address, port 2021, reachable only from taskworker hosts. The loop GETs http://<host>:2021/metrics every 5 s with a 2 s timeout through DriveCounterSource, reading node_disk_written_bytes_total and node_disk_writes_completed_total per metadata drive and node_disk_reads_completed_total and node_disk_writes_completed_total per HDD, the kernel counters of /sys/block/<dev>/stat fields 7, 5 and 1. A missing reading publishes nothing, as EVSB-M2-07 plans. SMART stays hourly on the textfile path, and remote-write to Mimir stays for monitor.

Changes: §19.6 counters row.

Questions: `plan-EVSB-counter-transport.md`.

### QD-481: `hash(network_id)`
*Proposed fill: a gap the agents filled; work builds on it.*

The first 8 bytes of SHA-256 over the id's 16 bytes, big-endian, mod 100, in one function every gate shares, EVS2-M10-05's `Format2Gate` included.

Changes: §19.11.

Questions: `plan-OPS-small-readings.md#2`.

### QD-495: tlsedge.yml's divisor for cap ÷ blocks
*Proposed fill: a gap the agents filled; work builds on it.*

tlsedge.yml gains blocks, a required integer of at least 1; tlsedge refuses to start without it. Its value is the number of lb hosts running tlsedge: each host's full-weight g1 block once, its beta block not at all, since §19.4's weights send 99% of a host's traffic to g1 and counting both would halve every endpoint cap. A process applies ceil(cap / blocks), at least 1, to concurrency and bandwidth; new-connection buckets stay per process.

Questions: `plan-TLS-small-readings.md#12`.

### QD-539: `p0_enforce` is in `sidecar.yml` and not in §19.11's list
*Proposed fill: a gap the agents filled; work builds on it.*

Keep `p0_enforce: {enabled: false}`, and add it to §19.11's list at the next records pass.

Changes: §19.11.

Questions: `plan-OPS-small-readings.md#3`.

### QD-574: How does a service block reach `vault/<env>/services.yml` when agents may not read vault?
*Settled by the agents from the design; work builds on it.*

The limit stands. Agents write each block as a fragment in `warp/services/sidecar-blocks/`, checked by warp's real loader on a synthetic base, and OPS-M2-03 builds `warpctl services apply-fragment`, which merges a fragment into the top version, allocates ports by warp's rules and prints a diff. The owner runs it against vault; that step stays on OPS's external list and each gate reports it open. No agent reads anything under vault.

Questions: `plan-OPS-vault-blocks.md`.

<a id="s20"></a>
## §20 Tiers, quotas, metering, and billing

### QD-020: Who writes a Team's next period, given `invoice.paid` arrives at least 72 h into it?
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

`RefreshTeamTransferBalances` writes each period's `team` grant and `team_credit` line at its 00:00:00 UTC anchor for every Team whose subscription is live with no unresolved payment failure. `invoice.paid` writes only the first period; on a cycle invoice it records the renewal's revenue, clears dunning and restores a line ended by a failure. `invoice.payment_failed` stops the next grant and ends the current line, so overage refuses at once while included bytes run out. §20.9 states what the job does. Exposure per unpaid Team is one period: its base, its seats and up to 10 TiB of line paid out at $3 per TiB.

Changes: §20.5; §20.9; D-QUOTA-8.

Questions: `plan-QUOTA-team-renewal-window.md`.

### QD-087: How does a lease's spent byte become a debit without counting twice?
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Carve. At each 60 s window the host runs one new branch of the reservation script that moves the window's used bytes, per balance in draw order, out of the lease's token into a token named for the journal row's `usage_id`, a no-op if that token exists. It sends (usage_id, balance_id, bytes) with the batch on the internal wire, so `UsageEvent` stays as engines see it. `ApplyUsageBatch` journals those rows, and the flush `release`s the token as it does a contract's. A killed edge's tokens lapse at 24 h with no debit, as FS-46 expects. No new table, column or Redis family.

Changes: §20.6; §20.14.

Questions: `plan-QUOTA-lease-debits.md`.

### QD-090: How is a day's transfer overage computed when four paths debit the line?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

`RollupServiceUsage` derives the row from the line, so every debit path feeds it and no settlement code changes. At each UTC day's close, take the network's `team_credit` balances ending within 7 d of that day, with used = start_balance_byte_count - balance_byte_count. The day's bytes are the sum of used now over yesterday's set and today's, less yesterday's stored total; store today's total over today's set. Keep C, the running sum of day's bytes, and write `team_transfer_overage` as round(C(d) / 2^30) - round(C(d-1) / 2^30), whole GiB, so rounding never accumulates. Both helper values are `network_service_usage` rows under meters `team_credit_window` and `team_credit_running`, which api-13 names and `GET /network/usage` hides. A debit counts on the day the pass first sees it.

Changes: §20.9; §2.8 api-13.

Questions: `plan-QUOTA-overage-accounting.md`.

### QD-094: What durable mark names a relayed contract, and how does it reserve with no added Postgres round trip?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

Set `payer_network_id` in the contract's one INSERT: no new column or statement, and payer plus no `transfer_escrow` row plus positive bytes names a relayed contract, since zero-escrow contracts set no payer. At close, read the payer's balances and each one's token before the close transaction. Teach `recoverRedisReservationWithFenceInTx` and `validateContractFreeSettlementOwnerInTx` that shape, and check every reader keyed on the payer (about 40 lines in server/model). Read credit from a per-process draw-order cache of 5 s. §20.6's cost row becomes "no Postgres round trip added on a warm cache, one read on a cold one", and connect-1 says the column is set here.

Changes: §20.6; §2.8 connect-1.

Questions: `plan-QUOTA-relayed-custody.md`.

### QD-143: "Active within 30 days"
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Recommended: a member is active if any client under its `member_id` has an `auth_time` within 30 days, stated in the billing terms, since an always-on device or a member's agent keeps that seat billed.

Questions: `plan-QUOTA-small-readings.md#11`.

### QD-164: §20.9's sites row and FS-46 omit three balance-order reads
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

All three follow `escrowDrawLess` behind `escrow_draw_order`. §20.9's sites row adds `deadlineEscrowRowsSql` (server/model/subscription_contract_scheduled_close.go:49-59), `proveRedisGrantExhaustion` (subscription_redis_exhaustion.go:179-185) and `zeroEscrowContractPriorityInTx` (subscription_zero_escrow.go:514). FS-46 adds a clause: a contract closed at its deadline keeps bytes on the pack before the line.

Changes: §20.9; FS-46.

Questions: `plan-QUOTA-draw-order-sites.md`.

### QD-180: evs bytes past every balance, and FI-13(a)'s "exactly once"
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

The rest of a debit overdrafts the last drawn in-window balance. With no in-window balance at all the bytes go unbilled, counted in `urnetwork_quota_unbilled_bytes_total`. FI-13(a) gains the exception: "barring an unclean producer exit, a batch dropped past its 10-min retry horizon, or a network with no in-window balance".

Changes: FI-13.

Questions: `plan-QUOTA-small-readings.md#5`.

### QD-295: The 14-day clock
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`NetworkDowngradeTime` is the end of the network's newest renewal of the tier it left.

Questions: `plan-QUOTA-small-readings.md#12`.

### QD-351: Nightly count against deltas
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The pass writes an absolute count, deltas landing during it are not replayed, and the next pass corrects them.

Questions: `plan-QUOTA-small-readings.md#6`.

### QD-356: `ReconcileSidecarCounters`
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The job recomputes `storage_over`, the connected set and spent marks, and reports row-counted capacities over their limits as a metric, refusing nothing.

Questions: `plan-QUOTA-small-readings.md#7`.

### QD-361: RESOURCE_EXHAUSTED over HTTP
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

HTTP 429 with the `QuotaRefusal` body and no Retry-After.

Questions: `plan-QUOTA-small-readings.md#13`.

### QD-430: Meter names
*Proposed fill: a gap the agents filled; work builds on it.*

`mx`, `smtp`, `evs`, `relay`, `team_transfer_overage` and `team_storage_overage`, beside the named `tls` and `team_seats`; the last two of the new ones and `team_seats` are also Stripe's `event_name`s.

Changes: §20.9; §20.14.

Questions: `plan-QUOTA-small-readings.md#2`.

### QD-488: `smtp_burst` holds one number for two windows
*Proposed fill: a gap the agents filled; work builds on it.*

New `pro.yml` key `smtp_burst_window`: 10 min on Community and Pro, 1 h on Team, beside `smtp_burst` 5, 50, 2,000.

Changes: §20.4.

Questions: `plan-SMTP-small-readings.md#6`.

### QD-491: §11.10's caps are §20.4 keys with no written names
*Proposed fill: a gap the agents filled; work builds on it. Also amends §11.*

Add to §20.4's sidecar_abuse: evs_subscribers_per_repo: 1000 and evs_repos_per_client: 500. The team directory's per-repo cap is the network's config_admissions instead, as §11.10 says. The per-repo cap counts distinct holders of {evsl_<repo_id>} inside the lease script. Past a cap the route answers a QuotaRefusal whose limit_key names the key, by §20.7's mapping.

Changes: §20.4 sidecar_abuse.

Questions: `plan-EVS1-subscription-caps.md#1`.

### QD-494: pro.yml keys for §13.9's per-visitor caps
*Proposed fill: a gap the agents filled; work builds on it. Also amends §13.*

sidecar_abuse: gains tls_visitor_concurrent: 64, tls_visitor_new_per_s: 20 and tls_visitor_aggregate_multiple: 4, the last applying to the /48 and /24 aggregates.

Changes: §20.4.

Questions: `plan-TLS-small-readings.md#10`.

### QD-496: The create cap's key and numbers
*Proposed fill: a gap the agents filled; work builds on it.*

`top_level_client_limit: 100` under each tier in pro.yml, read in place of `LimitTopLevelClientIdsPerNetwork`, with `network_top_level_client_limit` rows still overriding it.

Changes: §20.4.

Questions: `plan-QUOTA-sidecar-clients-store.md#2`.

### QD-510: Closure pacing's shape
*Proposed fill: a gap the agents filled; work builds on it.*

Each asking eraser holds one slot on a tail spaced 1/R apart. A refused upload keeps its slot, a taken turn takes a new slot at the tail, a slot lapses 5 minutes past its turn (setting `ClosureSlotHorizon`), and a per-second bucket of R still bounds the network when past-due erasers return together. §20.14's {sq_} row adds the tail.

Changes: §20.14.

Questions: `plan-QUOTA-small-readings.md#19`.

### QD-533: One lease per process
*Proposed fill: a gap the agents filled; work builds on it.*

`Quota.Lease` handles are ref-counted over one lease per process and (network, meter), and the last `Close` settles.

Questions: `plan-QUOTA-small-readings.md#16`.

### QD-538: `GET /network/usage`'s body
*Proposed fill: a gap the agents filled; work builds on it.*

`QuotaLimits`, `stored_byte_count`, `storage_over`, `spent`, and day rows `{usage_day, meter, quantity}` for up to 13 months, paged.

Changes: §20.14.

Questions: `plan-QUOTA-small-readings.md#10`.

### QD-544: The read-receipt budget counts through Quota.CountRate under two new keys
*Proposed fill: a gap the agents filled; work builds on it. Also amends §11.*

Add to sidecar_abuse: evs_read_receipts_per_repo_day: 256 and evs_read_receipt_bytes: 4kib. evs counts with ServiceHost.Quota.CountRate on the repo's network, key evs_read_receipts:<repo_id>:<UTC day>, debit id the push id, so a retry counts nothing twice. Past it: 429 with retry_after_ms to the next 00:00 UTC, as §11.12 says.

Changes: §20.4 sidecar_abuse.

Questions: `plan-EVS1-subscription-caps.md#3`.

### QD-546: Keys §20.4 only cites
*Proposed fill: a gap the agents filled; work builds on it. Also amends §12, §14, §11.*

QUOTA-M1-01's key table takes §12.7's `dns_changes_per_hour`, `dns_challenges_per_name_hour` and `dns_dkim_selectors`; plan-EVS1-subscription-caps' `evs_subscribers_per_repo` and `evs_repos_per_client`; plan-TLS-small-readings' `tls_visitor_concurrent` and `tls_visitor_new_per_s`; plan-SMTP-small-readings' `smtp_burst_window`; §14.7's breaker and destination numbers; and `evs_read_receipts_per_day` 256 a repo, from §11.12. Any area adds a key with one table row.

Changes: §20.4.

Questions: `plan-QUOTA-small-readings.md#1`.

### QD-547: §14.7's concurrency cap has no number
*Proposed fill: a gap the agents filled; work builds on it. Also amends §14.*

`smtp_destination_concurrency: 10` in `sidecar_abuse:`, per (sending address, destination /24), in edge memory; tune on M9's first runs.

Changes: §20.4 sidecar_abuse.

Questions: `plan-SMTP-shared-counters.md#3`.

### QD-548: Leaving spent
*Proposed fill: a gap the agents filled; work builds on it.*

A taskworker pass every 60 s, a setting, clears `spent_time` once any in-window balance has room, so a new grant reopens a network within about a minute.

Changes: §20.6.

Questions: `plan-QUOTA-small-readings.md#4`.

### QD-551: Team's names
*Proposed fill: a gap the agents filled; work builds on it.*

`SubscriptionTypeTeam` ("team") in `subscription_renewal`, and grant kinds `team` and `team_credit`, both added to `grantGrace`. The credit line carries `pro=false` and no `tier`, so it never confers the tier.

Changes: §20.5.

Questions: `plan-QUOTA-small-readings.md#15`.

### QD-552: `usage_id`
*Proposed fill: a gap the agents filled; work builds on it.*

A relayed row's `usage_id` is its `contract_id`; a batch row's is the first 16 B of SHA-256(batch_id || network_id || meter || balance_id).

Changes: §20.14.

Questions: `plan-QUOTA-small-readings.md#3`.

<a id="s21"></a>
## §21 Abuse, safety, and legal process

### QD-006: A stranger's report of CSAM or a threat to life can wait 7 days on Community
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Recommended: add both categories to §21.8's fourth row, 4 business hours on every tier, with one line in `AbuseSignalOfReport`, and ask counsel whether the weekend gap is acceptable. The pager stays as owner decision 134 set it.

Changes: §21.8.

Questions: `abuse-core-urgent-report-clock.md`.

### QD-008: Under a hold, does a user's network or client deletion delete the rows the hold covers?
*Decided by the owner: owner 2026-11-06. Also amends §2.*

follow Proposed as the rule (silent deferral). (The recommendation it replaces: Silent deferral. `RemoveNetwork` and `RemoveNetworkClient` on a held network read as done to the user, and in the deletion's own transaction copy the in-scope rows they delete (api-1, api-4, api-5, `network_acl_head`) into the hold's `copied_rows`. No refusal, hint or admin event. The repo shreds a deletion starts still run under owner decision 133. The idle client reaper is a TTL sweep, so it skips held rows. api-14 and §21.9 say so, and counsel sees it beside owner decision 133's condition.)

Changes: §21.9; §2.8 api-14; R-ABUSE-5.

Questions: `plan-ABUSE-hold-deletions.md#1`.

### QD-026: What values does a hold's `scope` take?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §11, §2.*

`scope` is the string `network`, or a list of 1 to 16 repo ids. A repo scope covers that repo's objects on every cluster and its gkm group. Server rows (tls-3, mx-2, smtp-3, api rows) are always covered by network. Counsel sets the scope from the order, defaulting to `network`. Scopes compare by containment: a repo stays until the latest `expire_time` of any hold that covers it. Readers treat an unknown or unparsed scope as the whole network.

Changes: §21.9; §11.8; §2.8 api-14; §2.8 evs-19.

Questions: `plan-ABUSE-hold-format.md#1`.

### QD-033: When strikes add up to suspending a network
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §14, §23.*

Recommended: accept items 3, 5 and 7 as landed. Item 3: "3 halts" counts the network's `mail_halt`, of any category, not a burner label's, and SMTP-M9-16 reads it the same way. Item 5: both copyright counts are per network, so a 2nd valid notice about another host kills the host it names; "valid" is any copyright row not lifted as wrong, "upheld" is review state `upheld`, counted per case. Item 7: while a kill stands on a host, a threat case adds nothing and a copyright notice is forwarded with no second kill; a kill that ended or was lifted stops this. Counsel reads item 5 beside §23.7's list.

Changes: §21.4; §14.8.

Questions: `abuse-core-policy-readings.md#3`, `abuse-core-policy-readings.md#5`, `abuse-core-policy-readings.md#7`.

### QD-036: Do holds reach connect-1's contract rows, given per-network keep rules cannot survive weekly drops?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §23.*

connect-1 joins `copied_rows`. At placement `AbuseHoldCopy` copies the `transfer_contract`, `contract_close` and `contract_close_report` rows naming a client of the held network that exist at placement, as compressed parts. The contract horizon reaper, `RemoveExpiredCloseEvidence` and the weekly partition drops call `AbuseHoldCopyPending` first and wait only while a hold placed before the range's end has an unfinished copy, so no keep rule is added and every drop stays whole. §21.9 and api-14 list these rows. Counsel sees this row beside §23.7's item.

Changes: §21.9; §2.8 api-14; §2.8 connect-1.

Questions: `plan-ABUSE-hold-contract-rows.md#2`.

### QD-038: How does a registrar, registry or law-enforcement notice enter §21's pipeline and page the rota?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §23.*

Both routes. (a) Registrar, registry and law-enforcement contacts name a company mailbox off the platform, for example legal@ur.io, the owner naming it, with a provider rule that fires the page; the rota files the case through the staff route. (b) `abuse.yml` gains `notice_senders`, domain to class: mail to abuse@ or postmaster@ whose DKIM verifies under a listed domain pages both rota members and opens a case, reading no body. (c) No mail or form text drives a kill: §21.8's machine host kill for a registrar's or registry's URL becomes a rota action inside the same 1 h. The public form offers no registrar or law-enforcement class.

Changes: §21.8; §21.16; D-ABUSE-3; D-ABUSE-5; §23.7.

Questions: `plan-ABUSE-notice-intake.md`.

### QD-049: What does a §21 suspension do at each gate, given only a customer can sign a `Suspend`?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §8.*

A §21 suspension is server state feeding §8.6's `hardDeny`, never a signed `Suspend` (I-4). One `abuse_action` fans out: `network_abuse_state = suspended`; a `*` kill; `SuspendZone`, so MX goes and senders retry; a mail halt from M9; every open contract closed; new contracts refused for sidecar subjects only, shares included; no `rev/`; evs and gkm untouched, so reads, writes, erasure and export continue; certificates kept unless the case orders revocation, so a lift restores service at once. §8.6's "as for §21's halts" is narrowed so it does not reach evs under a suspension.

Changes: §21.7; §21.10; §8.6.

Questions: `plan-ABUSE-suspension-effects.md`.

### QD-067: "Never the root" has no list of root and platform names to check against
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Add `protected_names: {roots: [...], platform: [...]}` to `abuse.yml`, ABUSE-M5-03's key list and §21.16, read into `AbusePolicySettings.RootNames` and `PlatformNames`. A target equal to a root is refused. A target equal to or under a platform name is refused. Once server requires sidecar, `IsReservedDnsLabel` also checks the first label under a root. Empty lists refuse every target.

Changes: §21.16; ABUSE-M5-03.

Questions: `abuse-core-protected-names.md`.

### QD-078: §21.10's record has no authentication, so a forged lift could be re-applied at a restore
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §19.*

Add `mac` to §21.10's record: HMAC-SHA-256 over the record's other fields as canonical JSON, under vault key `abuse_mailbox_mac_key`. §19.10's abuse step refuses, and prints, any record whose MAC fails or is missing, and the printed plan with its explicit apply stays. The same key covers the legal-request mailbox. Sealing alone would not do: a public key lets anyone seal a forgery.

Changes: §21.10; §19.10; D-ABUSE-7.

Questions: `plan-ABUSE-small-readings.md#16`.

### QD-088: `legal_request_mailbox` is read by §19.10 and named by no config
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §19.*

`abuse.yml` gains `legal_request_mailbox`, beside `abuse_mailbox`. It receives one record per hold placed, renewed or ended, as {event, case_id, network_id, kind, scope, place_time, expire_time}, sealed and MACed as the abuse mailbox's records are. §21.16's list and api-14 name it.

Changes: §21.16; §2.8 api-14.

Questions: `plan-ABUSE-small-readings.md#12`.

### QD-111: Trusted flaggers can trigger a machine kill, and §21 gives them no credential
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

`abuse.yml` lists `trusted_flaggers: [{id}]`. A vault file `abuse-flaggers.yml` holds, per id, the SHA-256 of a 256-bit key. `POST /abuse/report` takes `X-UR-Flagger-Key`, compared in constant time, and a match sets reporter class `trusted_flagger`. Each flagger is capped at `flagger_kills_per_day`, default 20, past which its reports take §21.8's ordinary row. Each kill's review shows the flagger id, and removing the line revokes it.

Changes: §21.8; §21.16.

Questions: `plan-ABUSE-small-readings.md#21`.

### QD-126: How abuse staff sign in and act
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §19.*

[plan-ABUSE-staff-surface] One staff route, `POST /abuse/action`, `x-internal: true`, its `kind` covering lookup, review, appeal decision, limit row, hold placement and renewal, legal request, production sign-off, restore-flag clear and mailed-action re-apply. Credential: a per-person bearer, kept hashed in vault file `abuse-staff.yml` as {reviewer_id, sha256, roles (reviewer, legal, engineering), expires}, at most 90 days old, compared in constant time. The lb refuses the route from outside the operators' addresses. Each read writes `abuse_access_log` before it answers, an appeal's reviewer must differ from the action's, and a production needs one legal and one engineering id. "Separate from ops" stays a process rule in v0, stated in §21.10, since no option stops someone holding vault or Postgres. [plan-ABUSE-small-readings#22] `bringyourctl abuse` is the staff client, with no web UI.

Changes: §21.10; §21.16; §19.4.

Questions: `plan-ABUSE-small-readings.md#22`, `plan-ABUSE-staff-surface.md`.

### QD-133: Do logs with a fixed ttl, evs-7 and ops-1, stay outside holds?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

They stay outside, and §21.9 says so plainly: "a hold does not reach evs-7's or ops-1's logs, which go at 7 d". A production still reaches them while retained. `TestEveryRetentionSweepHonorsHolds` lists both rows with that reason.

Changes: §21.9; §2.8 api-14.

Questions: `plan-ABUSE-hold-deletions.md#2`.

### QD-142: What sends role mail's auto-reply, when mx-4 keeps the envelope in memory?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §15, §14.*

Send nothing. For mail to abuse@ and postmaster@ that §14.8's header-only parse cannot attribute, the platform listener answers at end of DATA `550 5.7.1 Not read. Report abuse at https://ur.io/abuse` instead of 250 and drops the message unread. Attributed mail keeps 250 and its sealed copy, and <token>@rpt.bringyour.com mail is unchanged. The sender's own MTA returns that text to the person as a bounce, so §21.8's pointer arrives with no credential on the TCP 25 block, no backscatter from us, no third party and no stored address. §21.8's sentence becomes "the listener's refusal points senders to the form".

Changes: §21.8; D-ABUSE-5; §15.4.

Questions: `plan-ABUSE-auto-reply.md`.

### QD-194: §21.7's network standing has entry conditions but no exits or precedence
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Add to §21.7: `network_abuse_state` is derived. A state holds exactly while its Entry cell holds, re-evaluated at each action, appeal result and daily; `suspended` ends at its review. Where several hold, the first of suspended, probation, restricted, trusted, standard applies, since probation's mail rule is stricter than restricted's. A trusted network falls to standard when its Team lapses, its domain stops verifying or an action ends its clean 90 days.

Changes: §21.7.

Questions: `g0-density-text-alignments.md#9`.

### QD-195: "13 months after the case closes" hangs on a close no section defines
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2.*

A case closes when every action is lifted or upheld by review, or, with no action, when reviewed. `abuse.yml`'s `appeal_window`, default 6 months (DSA Art. 20's floor), bounds when an appeal may be filed; a filed appeal reopens the case, which closes again at its decision. The 13 months run from the last close.

Changes: §21.10; §2.8 api-14; §21.16.

Questions: `plan-ABUSE-small-readings.md#9`.

### QD-235: Where does a name wait while `ScreenName` sends it to review?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §12.*

Review is a refusal with a case. The route answers `QuotaRefusal{limit_key: screen_review}` with the case id and stores nothing in §12's tables. A reviewer's allow is an `abuse_action` of kind `screen_allow`, naming network and name, which `ScreenFacts` reads, so the caller's retry passes. On probation a review verdict is refused with no case (§21.6). Nothing reserves the name meanwhile.

Changes: §21.6; §21.7; §12.8.

Questions: `plan-ABUSE-review-held-names.md#1`.

### QD-289: What makes a network `restricted`
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A host, label or network kill, or a network halt, within 30 days, unless review lifted it as wrong. Not counted: a burner label's halt; a §21.4 `no strike` action, meaning a protective kill for an exposed panel and a compromise halt or kill; a quota suspension (plan-QUOTA-small-readings.md#17). The question's wording missed the no-strike case.

Questions: `plan-ABUSE-small-readings.md#4`.

### QD-291: Abuse ladder and clock readings ABUSE-M5-04 landed (items 1, 2, 4, 6 and 8 to 19)
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Accept items 1, 2, 4, 6 and 8 to 19 as landed in server/model/abuse_policy.go and abuse_clock.go. ABUSE-M5-05 chooses whether a `notice_forward` row is mailed. Where plan-ABUSE-small-readings#5 says copyright counts only upheld notices, that is §21.4's third rung; the second rung counts valid notices as item 5 defines them. Items 3, 5 and 7 are held apart under abuse-core-policy-readings#3, #5 and #7.

Questions: `abuse-core-policy-readings.md`.

### QD-292: T2 for FS-48 and FS-49
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Pure tests of `model`'s policy on an injected clock stand as T2, and `.stack/server-test.sh` runs the same schedules against Postgres.

Questions: `plan-ABUSE-small-readings.md#15`.

### QD-315: Escalation counts
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

An action counts toward §21.4's "2nd in 30 d" and "3 halts in 30 d" unless review lifted it as wrong. Copyright counts only upheld notices. A `no strike` action never counts. That sentence is §21.4's third rung; the second rung counts valid notices, as abuse-core-policy-readings item 5 defines them.

Questions: `plan-ABUSE-small-readings.md#5`.

### QD-316: "Mailed, as it commits"
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The record is sent straight after commit through api's and taskworker's SES path, `mailed_time` set; `AbuseActionPass` retries rows missing it each minute. It does not ride `account_message_outbox`, whose one-minute cycle widens §21.10's "seconds" gap.

Questions: `plan-ABUSE-small-readings.md#10`.

### QD-317: What "≤24 h, in business hours" counts
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

≤24 h, 72 h and 7 d are elapsed hours; a deadline landing outside business hours moves to the next open. ≤4 business hours counts open hours only. A kill at Friday's close comes due at Monday's open, 63 h later.

Questions: `plan-ABUSE-small-readings.md#1`.

### QD-318: `network_abuse_state` rows
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A row exists only for `restricted` and `suspended`. `probation`, `standard` and `trusted` derive from `network.create_time`, tier, balances and action history, and are cached. A network 7 or more days old that fits no other row reads `standard`.

Questions: `plan-ABUSE-small-readings.md#3`.

### QD-323: What a barred case shows the network
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A barred case shows the network its standing and nothing else: no case id, category, target or appeal link. `GET /abuse/cases` omits it, `POST /abuse/appeal` answers as for an unknown case, and `GET /abuse/status` shows standing only. When a sealing order lapses the notice goes out with its case id and appeal link, and the appeal window runs from that notice. A CSAM case stays barred.

Questions: `plan-ABUSE-small-readings.md#6`.

### QD-328: Closure growth's exact test
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`model.NetworkClosureBytesToday` is above zero, `network_quota_state.storage_over` is true, and the nightly count exceeds `model.NetworkStorageLimitByteCount`. One open case per network: a case already open takes no second. No machine action.

Questions: `plan-ABUSE-small-readings.md#17`.

### QD-350: `network_verified`'s owner user
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`network.admin_user_id` until TEAM-M6-02 names an Owner. Verified means a `network_user_auth_password` row with `verified` true, or a `network_user_auth_sso` row for Apple or Google. Wallet, seed phrase and guest rows do not count.

Questions: `plan-ABUSE-small-readings.md#19`.

### QD-378: `trusted`'s tests
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Tier `team`; a verified `network_domain` row; the network's `team` grant, not its line, in window across the last 30 days with no unresolved `invoice.payment_failed`; and no action in 90 days unless lifted as wrong. The question's `paid` test is not enough: `paid` is generated from revenue columns (server/db_migrations.go:1655), and the `team_credit` line carries revenue before anything is collected.

Questions: `plan-ABUSE-small-readings.md#18`.

### QD-379: A report that joins nothing
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A report naming no URnetwork host, address or connection leaves no `abuse_case` row, and the form answers the same either way, so it is no oracle for which names exist.

Questions: `plan-ABUSE-small-readings.md#7`.

### QD-499: The feeds' shape
*Proposed fill: a gap the agents filled; work builds on it.*

`abuse.yml` lists URL feeds, each a plain text list of URLs or hosts, at most 64 MiB a fetch, keeping only names under `<root>`. Which feeds, and their licenses, stay on the external list.

Questions: `plan-ABUSE-small-readings.md#14`.

### QD-500: How a lift appears in the mailed record
*Proposed fill: a gap the agents filled; work builds on it.*

A lift has its own `action_id`, `kind: lift`, and `target` holding the lifted action's id. No new field.

Changes: §21.10.

Questions: `plan-ABUSE-small-readings.md#11`.

### QD-501: The business-hours calendar
*Proposed fill: a gap the agents filled; work builds on it.*

`abuse.yml`: `business_hours: {zone: UTC, days: [mon, tue, wed, thu, fri], open: "09:00", close: "18:00", holidays: []}`; `mode: always` is M6's 24/7. main's zone is set with the rota's staffing.

Changes: §21.16.

Questions: `plan-ABUSE-small-readings.md#2`.

### QD-502: ur.io paths
*Proposed fill: a gap the agents filled; work builds on it.*

`/abuse` (the form), `/legal/law-enforcement`, `/legal/rfc3207-deviation`, `/legal/transparency`, `/legal/canary`.

Changes: §21.11.

Questions: `plan-ABUSE-small-readings.md#23`.

### QD-554: Where the Web Risk Update API's local state lives
*Proposed fill: a gap the agents filled; work builds on it.*

Taskworker memory, refetched in full on a cold start, so no row is needed and ext-6's view is unchanged. RAW diffs only, no Rice decoding.

Questions: `plan-ABUSE-small-readings.md#13`.

<a id="s22"></a>
## §22 Testing and verification

### QD-028: May `server/test-env.sh` attest all three masters of T3's private Redis Cluster?
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Extend portable mode to take a list of Redis authorities. Each must be loopback on a port above 50000, pass `test_env_refuse_loopback_tunnel_endpoint` and the probe, and be attested by address in `WARP_TEST_ENV_ATTESTED_ADDRS`, which has room for 8. test_env_dial_guard.go stays as strict, and no other mode changes. The list stays private to the sidecar stack.

Changes: server/test-env.sh; the brief's guard limit.

Questions: `plan-TEST-t3-redis-attestation.md`.

### QD-135: §22.6 names mailgun/proxyproto, which has no license and which §4.7 refuses, and server links it in production
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §4.*

Recommended: change §22.6's PROXY bullet to name a second reader written from haproxy's proxy-protocol.txt, which is what landed, and record the one-off comparison in `.stack/scratch/tls-hello/proxydiff/`. Separately the owner decides what to do about `server/connect/transport_pp.go`, which links the unlicensed module in production: one email asking mailgun for a license, or a replacement.

Changes: §22.6; §4.7 under option 3.

Questions: `tls-hello-mailgun-proxyproto-license.md`.

### QD-200: §22.8's hdd run measures what one offered load achieved, not capacity
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §19.*

§22.8's hdd row gains a capacity step before the mix. At year two's 1:4 PUT to GET ratio, drop the page cache on every host before each step and read no object twice within a step; offer load in 10-minute steps, each 25% above the last, until achieved drive operations rise under 5% from the step before. Capacity is that plateau, by the same /sys/block stat fields 1 and 5, and it is what §19.6 publishes, with p99 at the plateau recorded. The 1 h runs at year one's and year two's mix with admission on follow unchanged.

Changes: §22.8 hdd row; §19.6 hdd row.

Questions: `g0-recheck-0-hdd-trigger.md#2`.

### QD-210: "Once C3 is tested" names no test
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §23, §6, §20.*

Add FS-126 to §22.8 (§6, T2+T3, M6-out) and to §23.6's M6 schedule: with C3 on, a forged ControlId frame over P2P is dropped; a same-network pair moves from relay to P2P and back under a live RPC and stream, its session key unchanged; Hello and HeadCheck hold across the move; and bytes on P2P debit nothing (§20.6). D-PROTO-10's "P2P is tested" means FS-126 passes.

Changes: §22.8; §23.6.

Questions: `plan-PROTO-p2p-milestone.md#2`.

### QD-239: What runs the nightly form, with no CI and no nightly job?
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

A launchd job running `sidecar/test.sh --cadence nightly` on a host the owner names, with T3's private stores on that host. During this build each gate sweep runs that form. It never takes `tests/network-intensive-suite-lock.sh`.

Changes: §22.15.

Questions: `plan-TEST-cadence-runner.md#2`.

### QD-264: How does a T3 row move time on stores that keep real time?
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

T3 keeps each row whole and translates time in one reviewed file, server/sidecart3/clock.go. The Blobs wrapper records each key's write on the schedule's clock and returns it as `LastModified`. `Advance` shortens Redis TTLs by `PEXPIRE` over the families a row names. api takes the clock through a test seam beside `DenyPostgresForTest`. A clause that depends on Postgres `now()` or a script's Redis `TIME` after an `Advance` runs on T2 only, since neither can be moved. The catalog's `store-clock` flag marks every translated clause, gate reports say so, and FS-114 and §22.9's file-cluster suite never use the wrapper. §22.8's `real` rule gains that sentence.

Changes: §22.8; D-TEST-10.

Questions: `plan-TEST-clock-seam.md#2`.

### QD-634: How does `ur evs rekey` re-checkpoint the files of a git-mode ref, which takes writes only as git pushes through the local tier?
*Decided by the owner on 2026-11-10, asked one question at a time.*

A rekey of a git-mode ref is a git-mode push with no commit, the REKEY shape of DESIGN-DETAILS 8.2: it keeps the tip, and its changes only re-checkpoint files under the current generation, each new entry's sealed mode, oid and name equal to the standing one's. Any writer's device can send it, a head-mode one included. EVS1-M2-48 builds the push rules and removes gkm_rekey.go's git-mode skip, after which §22.7's row holds for git-mode refs too.

Changes: DESIGN-DETAILS.md section 8 stands as written; EVS1-M2-48 builds it and removes the skip.

Questions: `keys-m2-26-rekey-git-mode-refs.md`.

### QD-303: Porcupine stays out of the sidecar module
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

The import sits in server's tests, and `sidecartest/fault` keeps a plain recorded history. EVS1-M2-42's `dependencies.yml` row is not needed.

Questions: `plan-TEST-small-readings.md#2`.

### QD-311: A statement's id sits at field 2, behind its header
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

StatementHeader stays field 1 and ids follow at field 2. §22.6's target reads 'with equal bodies': both statements carry one header and one id, so the whole bodies match and only the type refuses them, as TestGrantRevokePresentedAsOwnerConfirmIsRefused does.

Changes: §22.6.

Questions: `protos-bridge-statement-field-one.md`.

### QD-338: `evs's gate off`
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §4.*

The engine's gate-off seam and `Net.SetEvsGate` exist only under build tag `sidecar_testhooks`, so release builds carry neither the setting nor a config key, and §4.7's hygiene row fails a release leg that links the tag. §22 picks up the name.

Changes: §22.7.

Questions: `plan-TEST-small-readings.md#9`.

### QD-340: Forging clauses inside T2+T3 rows
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

Those clauses of FS-38, FS-102 and FS-124 run on T2, their honest clauses and twins on T3, and the catalog flags each.

Questions: `plan-TEST-small-readings.md#6`.

### QD-342: §22.10's ladder row omits wrap_aad, which §10.4's ladder row requires
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §10.*

The artifact's ladder row reproduces KeyDelivery's wrap_aad as well as GenWrap's, LeafWrap's and GenLink's AAD, as §10.4 says. KEYS-M2-11 already plans it; design-records aligns §22.10's row.

Changes: §22.10 ladder row, wording only.

Questions: `g0-recheck-0-readerkey-forgery.md#3`.

### QD-346: §22.7's actions row omits evs_drop_preview on a secret repo
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §16.*

§16.5 and §16.6 refuse every evs tool on kind secret, so §22.7's actions row covers all of them: add evs_drop_preview on a secret repo and on the config. The case lands with MCP-M10-01, when the tool exists.

Changes: §22.7.

Questions: `g0-recheck-2-mcp-config-read-scope.md#2`.

### QD-347: A row's purpose
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A row's purpose is its `why`, and a withdrawn row's single `withdrawn` key passes.

Questions: `plan-TEST-small-readings.md#4`.

### QD-363: Schedules live in non-test files
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

A row on T2 and T3 is one exported `fault.Builder` in a non-test file. Other plans' `sidecartest/fault/fsN_test.go` names hold only the thin T2 test.

Questions: `plan-TEST-small-readings.md#1`.

### QD-372: §22.9 and FS-97 drop D-TEAM-29's "at least one"
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

D-TEAM-29's "at least one" holds: a Worker no group of the admitting device seated is never revoked in that act. Add the words at 22-TEST.md:2603 and at FS-97 (22-TEST.md:2065), which the question missed, and assert the empty case.

Changes: §22.9; FS-97.

Questions: `g0-density-text-alignments.md#6`.

### QD-374: Does D-TEST-1 mean T3's schedules gate every merge?
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

T1, T2, T4 and T3's store suites gate merges. T3's FS rows run nightly and at each Gn-out, and the explorer takes 10 seeds a merge on T2 rows and 100 a night on T3 rows.

Questions: `plan-TEST-cadence-runner.md#1`.

### QD-423: A `+T4` row
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

It is T4's when the SDK cell exists. Until M8 its T2 and T3 parts gate, and the gate report shows T4 as open.

Questions: `plan-TEST-small-readings.md#10`.

### QD-424: `ur tun ip auto` waits for its §22 evidence
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`auto` refuses behind `BridgeComponentSettings.AutoAddressEnabled`, false, until §22.9's Browsers check shows no ICE candidate in the overlay block. An explicit `<ip>` and an admin's assignment work.

Questions: `plan-BRIDGE-small-readings.md#18`.

### QD-536: `metadata_list.yml` location
*Proposed fill: a gap the agents filled; work builds on it. Also amends §2.*

At the sidecar repo root, generated byte for byte from §2.8's fenced block by `make metadata`. A row changes only through design-records.

Changes: §22.7.

Questions: `plan-TEST-small-readings.md#3`.

### QD-587: Classify is in-repo, not bart
*Settled by the agents from the design; work builds on it.*

Build an in-repo table in `device/`: prefixes flattened at build time into sorted disjoint ranges with a binary search, held to §22.5's ≤50 ns at 1,000 prefixes.

Questions: `plan-BRIDGE-small-readings.md#1`.

### QD-594: D-TEST-5's synthetic main network
*Settled by the agents from the design; work builds on it.*

No task builds it: it is Later.

Questions: `plan-TEST-small-readings.md#8`.

<a id="s23"></a>
## §23 Phasing, milestones, and rollout

### QD-132: When does the segment placement get a design and a home, and what is its lead time?
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §19, §11.*

Recommended: open a tracked item now, as the next metadata cluster has. §23.7 gives it (due: before the projected crossing; start: M3's exit, when the hdd run first gives an admitted throughput) and a lead time of 26 weeks, monitor's setting hdd_trigger_lead_days = 182. A new Q-OPS item holds the placement's design, due within 8 weeks of M3's exit, §23.4's Later list and §19.18 name it, and the rota owns the page.

Changes: §23.7; §23.4 Later list; §19.18; §11.22; Q-OPS-2 residual.

Questions: `g0-recheck-0-hdd-trigger.md#3`.

### QD-247: FS-25's gate legs are due at M3-out, but the table, the route and the only gated effect arrive at M5
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §22, §16, §19, §7.*

Option 1. §16.18's M4-M9 row says `approval_use` and `POST /approval/cancel` are built dark at M3 under `sidecar_pending` and register with MG5 at M5's Gn-out (D-OPS-6 allows it, and T3 sets the tag, §19.7). §23.6's M3 row and FS-25's row say: at M3-out the gate legs (a gate's response lost after COMMIT, two api instances racing) run on real Postgres through `model.ConsumeApprovalUseInTx` with a test effect in the same transaction, and the cancel case runs through the real `POST /approval/cancel` route with §7.4's allowlist on; at M5-out the same legs run again through `POST /dns/records` (MCP-M5-01). §22.8's `real` row names this one exception until M5-out. The test effect pre-authorizes nothing: the spend check and the claim run as in production. §19.7's MG5 stands.

Changes: §23.6 M3; §22.8 FS-25; §22.8 real; §16.18 M4-M9.

Questions: `plan-MCP-fs25-gate-before-dns.md`.

### QD-274: Keep §23.8's no-duplication clause as written, or name the duplication the design keeps on purpose
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §22, §7, §9, §11, §17, §2, §3.*

Recommended: amend §23.8's clause to "no content duplicated across sections (each item in its owning section, cited elsewhere), except §2.8's published list, §3.7's flows and Requirements rows". design-records then moves the test lists out of Interfaces subsections into §22 first (11-EVS.md:3098, 17-BRIDGE.md:528, 09-SOCK.md:393, 07-TEAM.md:990) and turns accidental restatements into citations, before M2's Gn-in.

Changes: §23.8; §22; §7.17; §9.15; §11.20; §17.16.

Questions: `g0-density-rule-direction.md`.

### QD-341: Holds before counsel
*Proposed reading: the agents' reading of text the design leaves open; work builds on it.*

`abuse.yml`'s `holds_enabled`, default false, refuses placement until counsel confirms (§23.7). Readers of `hold/` need no gate: no object, no effect.

Questions: `plan-ABUSE-small-readings.md#20`.

### QD-401: Which milestone owns gen packs
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §19, §22.*

[g0-recheck-2-gen-pack-trigger#2] Gen packs are not in this build and have no task or FS row. Add "gen packs at §19.9's gen trigger" to §23.4's Later paragraph. If §22.8's M2 count projects the trigger inside a year, raise that at M2's exit. [plan-coverage-section-later-rows] Every section's Later row stays out of M0-M10, recorded in OUT-OF-SCOPE.md, C7 and gen packs included. A section's Later uses the word as §23.4 does, and §23.16 makes work after M9 and M10 §23.4's Later.

Changes: §23.4.

Questions: `g0-recheck-2-gen-pack-trigger.md#2`, `plan-coverage-section-later-rows.md`.

### QD-482: Enums that give names to values fields already carry as uint32
*Proposed fill: a gap the agents filled; work builds on it.*

Keep EvsPushFlag, EvsLocatorKind, EvsVersioning, EvsWindowFlag, SmtpPreambleCode and SmtpProofCode as landed. Their fields stay uint32 on the wire, they add no number, and D-PHASE-9's lint reads them.

Questions: `protos-services-unwritten-numbers.md#6`.

<a id="s0"></a>
## No section named

### QD-007: A stray link stops all landing on two repositories
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

[connect-m1-stray-self-link] Someone with authority over the main checkouts runs `rm /Users/builder/urnetwork-sidecar/connect/connect` and `rm /Users/builder/urnetwork-sidecar/userwireguard/userwireguard`, with no `-r` and no trailing slash, since `rm -r` on a trailing slash follows the link and deletes the checkout. `glog/glog` and `gvisor/gvisor` are ignored by git and can go in the same pass. Then `track-land --merge connect-m1` runs. `track-land` keeps its check, and later loops use `ln -sfn`. [connect-c14-c9-stray-symlink-blocks-landing] Duplicate of connect-m1-stray-self-link: answer that one. Once the link is gone, `track-land --merge connect-c14-c9` runs as normal.

Changes: BRIEF.md Where you work, only under options 2 and 3.

Questions: `connect-m1-stray-self-link.md`, `connect-c14-c9-stray-symlink-blocks-landing.md`.

Not folded (2026-11-16): it changes only the run's BRIEF.md and the main checkouts' stray links, outside design/source/; DESIGN.md states nothing about the build machine's checkouts, so nothing of it belongs there.

### QD-052: Seven sdk worktrees under ~/urnetwork/temp were relinked by a mistaken `git worktree repair`
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Recommended: run the question file's restore loop, which writes fourteen one-line files, checks each before writing, and uses no `git worktree` command. Add a line to the brief: no agent runs `git worktree repair` or `prune` in a monoroot clone whose admin directory holds entries copied from `~/urnetwork`.

Changes: BRIEF.md hard limits.

Questions: `wire-consumers-sdk-worktree-links.md`.

Not folded (2026-11-16): it changes only the run's BRIEF.md and a clone's worktree links, outside design/source/; DESIGN.md states nothing about the build machine's worktrees, so nothing of it belongs there.

<a id="later"></a>
## Later decisions

Decisions taken after this file was generated, each naming the section it folds into. A design-records track folds the ones that name its sections, with that section's items above, and deletes them here.

§2.8's block holds the published list whole since 2026-11-16 (v26): the track for §2 and §3 wrote into it every line that items here and above had added to metadata_list.yml ahead of a fold through check's additions, list versions v12 to v25 (QD-040, QD-720, QD-724, QD-725, QD-743, QD-746, QD-763, QD-764, QD-765, QD-798, QD-819, QD-828, QD-830, QD-840 and DESIGN-DETAILS 17.2.16), and check's additions list is empty. Those items' §2.8 words are therefore done; their other parts fold with their sections, and a later row change is written in the block and copied by `make metadata`. The §10 fold wrote QD-857's v31 lines (cert-1's name failure backoff), which check's additions had published, into the block the same way on 2026-11-16, its entries leaving check's list, and took v32 for itself; QD-857's §13 parts were folded with §13 (owner decision 430). The §11 fold wrote QD-199's smtp-4 words, which SMTP-M9-16 had published through check's additions, into the block the same way, in the list's v34, after its own v33; QD-199's §14 and §20 parts were folded with §14.

### QD-652: Should closure pacing admit by seat, each seat good only in its own second, in place of a bucket that admits by arrival?
*Decided by the owner on 2026-11-10, asked one question at a time. Folds into §20 Tiers, quotas, metering, and billing.*

Closure pacing admits by seat. A seat is a 1/R cell at the tail of the network's pacing, good from its instant to the end of its calendar second; a seat is handed out only in a second with a free cell; an eraser whose seat is due takes, and nothing else is checked, so arrival order decides nothing. A refusal is not recorded under its debit id, so the same upload asks again. An eraser that misses its seat's second by more than the cell's tolerance (250 ms to 1 s at R = 4) is seated again, at once while the second has a free cell, one round later in a full network. Reading 19's 5-minute horizon and its setting go; the steady state is the landed one (k erasers each every k/R s). QUOTA-M2-14 changes QuotaClosurePacing, the fake, the {sq_} script and quotasuite's pacing cases together. This answers quota-m2-03-pacing-boundary-order with a fourth option and quota-m2-01-rate-key-grammar #3 with its other reading.

Changes: DESIGN-DETAILS.md section 13 stands as written; QUOTA-M2-14 builds it; §20.7 closure and wait rows (design-records).

Questions: `details-13-pacing-seats.md`, `quota-m2-03-pacing-boundary-order.md`.

### QD-653: Should bytes a lease spent under a reservation that has since lapsed go unbilled, and should a lease's own tokens live 15 minutes instead of 24 hours?
*Decided by the owner on 2026-11-10, asked one question at a time. Folds into §20 Tiers, quotas, metering, and billing.*

No lease byte is debited without its carve: a batch is posted only once its carves answered; bytes whose reservation was gone are dropped from the event, counted in urnetwork_quota_lease_unbilled_bytes_total and alerted; ApplyUsageBatch refuses a lease meter's event its carves do not cover. A lease's own tokens live 15 min and are extended every 5 min while the lease lives, and the host stops spending a token's bytes 30 s before it could lapse; carved tokens keep 24 h. The cost is under-billing of at most one window's bytes a host during a Redis outage as seen from that host; a dead edge's hold returns in 15 min. Lease.tla holds NoOverdraw only with this. QUOTA-M2-07 and QUOTA-M2-15 build it; landed ApplyUsageBatch and the fake's lease excess change.

Changes: DESIGN-DETAILS.md section 13 stands as written; QUOTA-M2-07 and QUOTA-M2-15 build it; §20.6 leases and loss rows, E-d (design-records).

Questions: `details-13-lease-lapse.md`.

### QD-654: Should a lease draw more than 64 MiB at a time when its traffic is fast?
*Decided by the owner on 2026-11-10, asked one question at a time. Folds into §20 Tiers, quotas, metering, and billing. Also amends §2.*

A lease's draw is 64 MiB (16 MiB on Community) or, when that is more, 4 s of the lease's own measured rate rounded up to a multiple of it, at most 16 times it (1 GiB; 256 MiB on Community), renewed with a quarter of the draw or 2 s of traffic left, whichever is more. A slow lease draws as §20.6 has it; a fast one renews about once per 4 s with 2 s to do it. A lease can hold up to 4 s of its traffic unspent, which a Redis loss can over-admit for it. §20.6's draw row and api-13's published sizes ('64 MiB to 1 GiB, 16 to 256 MiB on Community') change (design-records). QUOTA-M2-07 builds it.

Changes: DESIGN-DETAILS.md section 13 stands as written; QUOTA-M2-07 builds it; §20.6 draw row and §2.8 api-13 sizes (design-records).

Questions: `details-13-lease-draw-size.md`.

Partly folded (2026-11-10): §2.8 api-13's sizes landed with QD-657; §20.6's draw row waits for §20's fold.

### QD-077: X's pin of Y's ShareKey and Y's pin of each target host's identity key have no signed home
*Accepted by the owner on 2026-11-06, in bulk as recommended. Folds into §17 IP addresses, subnet routing, and port forwarding.*

The wire, which waits on the code: §17.9's fence takes `message BridgeShareGrant { bytes share_id = 1; bytes grant_id = 2; bytes share_public_key = 3; bytes target_table_sha256 = 4; bytes table_key = 5; }` once bridge.proto declares it, and bridge.proto gains `BridgeAliasBody.host_identity_public_key = 5` with the share seal's `BridgeShareTargets` and `BridgeShareAliases` (QD-108), which no DESIGN.md fence writes. The rest is folded (2026-11-10): §17.8's BridgeAlias, §17.9's share pins, shares paragraph and target row, a comment in §17.9's fence, §8.11, §7.9's repo files and FS-38.

Changes: §17.9's fence; bridge.proto.

Questions: `plan-BRIDGE-share-pins.md`.

Waits on: bridge.proto's share messages (BRIDGE-M6-03 to -05), the fence line landing in one change with them, as protocol's fence test holds the two together.

Not folded (2026-11-16): the ```proto fence for BridgeShareGrant in §17.9. bridge.proto now declares it with fields 1 to 9 (QD-670's 6 to 9 among them), but its declaration, with the share seal's bodies and `BridgeShareAccept`, is held by `testUnfencedFence` in protocol/design_unfenced_test.go, and a fence for a message listed there fails protocol's fence test until a code track moves the message out of that list in the same change, which a design-records track may not do. The fields are folded as text, with their numbers, in §17.9's share pins block (owner decision 475), and §17.9's fence comment says what joins it.

### QD-677: How should the soak count orphan objects by orphan GC's own definition, when evsservice has no count that deletes nothing?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §22 Testing and verification.*

EVSB adds a dry form to evsservice/gc_orphans.go: OrphanGc.CountRepo(ctx, repo *OrphanGcRepo) (*OrphanGcResult, error) runs steps 0 to 4 and step 5's selection, issues no DELETE, and reports CandidateCount and the count of those no pidx/ entry introduces, sharing orphan GC's one definition. The soak (server/local/sidecar-soak) implements its orphanCounter through it per repo over the nightly pass's listings and compares what GC would judge orphan, past the horizon, at the baseline and at the end. Until it lands the orphan signal reads open, as built. A data-lane follow-up of about forty lines.

Changes: data-lane follow-up: OrphanGc.CountRepo in evsservice/gc_orphans.go; server/local/sidecar-soak's orphanCounter wired to it.

Questions: `test-m2-03-soak-orphan-count.md`.

### QD-706: When does the sweep that moves the drafted code's constant tunables into settings objects (QD-702) run?
*Decided by the owner on 2026-11-11, asked one question at a time. Folds into §23 Phasing, milestones, and rollout.*

The sweep that moves the drafted code's constant tunables and limits into settings objects (QD-702) runs in the review phase, area by area as the review reads each area, not during the draft phase. Until then new code follows QD-702 and every track moves the constants in the files it touches (BRIEF.md); the remaining constants stay in drafted code. The 2026-11-11 scan (.stack/scratch/settings-sweep-scan-2026-11-11.json) lists about 801 constants in 351 sidecar files that no remaining task names; the review phase also sweeps the run's code in server, connect and sdk.

Changes: review phase: one settings sweep per area, from the 2026-11-11 scan.

Questions: `owner-settings-sweep-timing.md`.

### QD-726: What bytes does a sealed §21.10 record carry, and where in vault do its seal key and MAC key live?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §21 Abuse, safety, and legal process.*

A §21.10 record is sealed with HPKE-XWing as smtpedge's sealed report copies are (QD-441: KEM 0x647a, HKDF-SHA256, AES-128-GCM, base mode), info "UR abuse 1.0 record", body u8(1) || enc (1,120 B) || ct, the record's canonical JSON with its HMAC-SHA-256 MAC (QD-078) inside the plaintext. Vault file abuse-mailbox.yml holds abuse_mailbox_mac_key (32 random bytes, base64) and abuse_mailbox_seal_public_key (1,216 B, base64), mounted on api and taskworker only; the private key is held offline beside §19.10's restore runbook and is reachable by no running service. The mail is a text/plain body of the base64, through api's and taskworker's SES path. The legal-request mailbox (QD-088) takes the same seal and key file.

Changes: the production AbuseRecordMailer seals and sends (ABUSE-M5-03, -05); the owner creates abuse-mailbox.yml in vault and keeps the private key offline (an outward action).

Questions: `abuse-m5-03-record-seal.md`.

### QD-744: Should §19.6's rule (3) hold a failed DELETE's key until every commit of it has answered and been reverted, since TLC finds two DELETEs on one key breaking FI-30 under the rule as written?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §19 Server services.*

§19.6's rule (3) holds a failed DELETE's key until every one of its drive commits has answered and each that landed has been reverted, with no revert after release; a failed PUT keeps rule (3) as written (released once the drives that may still hold it number under N/2). Nothing of a failed DELETE then lands or reverts once another request can see the key, so FI-30's NoStaleQuorum holds for two DELETEs on one key, which §11.7's marker collection, v1's purge and the drop job rely on. The cost, a DELETE whose commit stalled on a frozen host holding its key until that host answers or its drives are replaced, is paid only by background jobs' unconditional DELETEs; D-OPS-20's Why and FI-30's last clause say so, with section 2's per-commit stamp (DESIGN-DETAILS 2.4, 2.8). The in-house MinIO build already holds a failed DELETE so (EVSB-M2-22, minio e7539a6e5).

Changes: §19.6's rule (3), D-OPS-20's cost and FI-30's last clause (design-records, with DESIGN-DETAILS 2.8's text); StoreSettle.tla models the held DELETE and passes TLC with DELETEs in the run (M2's Gn-in).

Questions: `evs-models-settle-stalled-deletes.md`.

### QD-751: Should certs renew stay on lego v4.35.2, the release certs issue runs, until someone checks lego v5's CLI, given that D-OPS-12 names v5 and v5 rejects the flags both commands pass?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §19 Server services.*

sidecarctl certs renew and warpctl certs issue stay on goacme/lego v4.35.2, the release production runs, with certs issue's exact flags plus --server, held together by TestCertsRenewLegoArgsAreTheImagesCli and TestCertsRenewRunsTheLegoReleaseCertsIssueRuns; D-OPS-12's lego v5 is recorded as the target. The move to v5 is one change to both commands and both tests, made once someone allowed to fetch the image has read v5's --help or run one order against Let's Encrypt staging (an outward action outside this run). Meanwhile renewals send no RFC 9773 replaces, which costs the CA's rate-limit exemption for a renewal it asked for and does not change when a certificate renews; sidecarctl reads ARI itself.

Changes: D-OPS-12 names v5 as the target, v4.35.2 as what runs (design-records); the v5 move is an owner or ops action outside this run.

Questions: `ops-m5-07-lego-v5.md`.

### QD-752: Where does QD-128's competition migration live on server's `sidecar` branch, and in how many steps?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §19 Server services.*

QD-128's competition migration lands in two steps. The permissive step, replacing competition_v2_source_graph_valid and competition_v2_source_authorized so a source graph of ten keys, or of eleven with sidecar, passes, goes in MG0's pending part (db_migrations_sidecar_pending.go) and registers with MG0 at M0's Gn-out; with it land server's Go list of eleven, its digest and the evaluator scripts. The tightening step, requiring eleven, is a cleanup migration once every competition job runs a release that sends eleven, as connect/CODESTYLE.md's additive-then-cleanup order says. §19.7's MG0 row gains the competition entry, and TestSidecarGroupsAreAdditive admits a function replacement that only widens a guard. Evaluator images are rebuilt from the Gn-out's commit; that rebuild and the cleanup's deploy are outward steps outside this run.

Changes: §19.7's MG0 row gains the competition entry (design-records); the permissive migration in MG0's pending part, with server's Go list, digest and evaluator scripts; TestSidecarGroupsAreAdditive admits a widening function replacement.

Questions: `wire-consumers-competition-migration-home.md`.

### QD-753: Who builds the two file-cluster signal sources monitor reads that no task owns: the minio fork's heal-debt export, and a scrape of each cluster's MinIO node metrics into Mimir?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §19 Server services.*

Both file-cluster signal sources get builders. A minio task builds the fork's half of QD-035: er.addPartial sets SetIndex and PoolIndex, cmd/mrf.go exports per pool and set the partial-write queue's depth, its dropped entries and its unclean starts, and the fork exports a last-full-heal time per cluster, so §19.6's degraded and at_risk can end when a full heal ends; monitor exports them as urnetwork_filecluster_mrf_depth{cluster,set} and the two counters, and EVSB-M3-01's fileClusterStateProbe.healDebt reads the queue. An xops task grows EVSB-M2-04's playbook-file-clusters.yml with a fluent-bit prometheus_scrape of each cluster's MinIO node metrics (/minio/v2/metrics/node) with a bearer token from vault, add_label cluster <id> and job file_cluster_minio, which SIGNALS.md §29.3's contract and filecluster-settle read from Mimir. Until both land, the owner's interim stands: heal debt reads unknown, never zero.

Changes: a minio task: the fork's partial-write queue export and last-full-heal time; an xops task: the node-metrics scrape in playbook-file-clusters.yml; monitor's queue reader in fileClusterStateProbe.healDebt.

Questions: `evsb-m3-01-file-cluster-signal-sources.md`.

### QD-754: How do §19.8's business-hours pages reach the rota, when the pager pages only at any hour?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §19 Server services.*

§19.8's business row pages the rota in business hours: OPS-M3-01's pageClasses rows gain an hours field, any or business, and PagerAlertNotifier holds a business-hours page until the business calendar opens (model's AbuseCalendar, abuse.yml's review hours, or a pager-service schedule when one is chosen), then pages, and resolves it as usual, with the pager's dedup and retry unchanged. A page whose alert resolves before the calendar opens is dropped. The business rows join by a table row each: filecluster-drive-dwpd-business, filecluster-drive-rating-short, a cluster's projected exhaustion within its move tool's lead time or at its cohort limit, a segment cluster's hdd crossing (g0-recheck-0-hdd-trigger #1), and an NS failing an hour (plan-DNS-running-ns, DNS-M5-17's).

Changes: OPS-M3-01's pageClasses rows gain hours; PagerAlertNotifier holds business pages until the calendar opens; the business rows move from Slack warns to pages.

Questions: `evsb-m3-01-business-hours-pages.md`.

### QD-755: MLS hands its 12-byte AEAD nonces to testHookSecret, which the privacy capture refuses as findings: should mls_* stop hooking nonces, or should the capture search a 12-byte secret?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §22 Testing and verification.*

The MLS subset stops passing its 12-byte AEAD nonces to testHookSecret: mlsCipherSuite.expandWithLabel (mls_ciphersuite.go) takes a hook flag, false for the three nonce derivations RFC 9420 makes (ratchet_nonce in mls_secrettree.go, sender_data_nonce in mls_secrettree.go, welcome_nonce in mls_keyschedule.go), and every secret a nonce is derived from stays hooked. The privacy capture's rule stands: a secret under 16 bytes is refused as a finding, so no test passes on a value it could not search for (TEST-M1-05). §22.4's 'at every key creation, derivation and unwrap' reads keys, which a nonce is not.

Changes: the MLS subset's nonce derivations unhooked (mls_ciphersuite.go, mls_secrettree.go, mls_keyschedule.go); TEST-M2-11's S3a and S4a run whole under sidecar_testhooks.

Questions: `test-m2-11-mls-nonce-hooks.md`.

### QD-756: On a one-process cluster, the minio fork's settle build takes a DELETE past its deadline and crashes in its stash sweep: is a one-process cluster in scope, and whose fix is it?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §19 Server services.*

A one-process MinIO cluster is out of scope for production, since §19.6 builds every cluster from 4 hosts (owner decision 145's whole clusters): the in-house build refuses to start one in settle mode, naming the rule. Its nil lock server is fixed whatever the shape: (*localLocker).SettleRows and the stash sweep (settle-locks.go, settle-drive.go) never dereference a nil locker. T3's second metadata cluster, meta-2, becomes a 4 x 2 cluster like meta-1, so FS-63's second-cluster cases and EVSB-M2-17's suite run on a multi-host meta-2, and the suite's one-process path goes.

Changes: §19.6 says a cluster in settle mode has at least 4 hosts (design-records); the minio fork refuses a one-process cluster in settle mode and never dereferences a nil locker; T3's meta-2 becomes 4 x 2 (server/local/file-cluster-t3).

Questions: `evsb-m2-19-one-process-cluster-settle.md`.

### QD-759: Must server's api answer a request whose Postgres connection a restart cut with 503 and Retry-After, rather than its fixed 500?
*Decided by the owner on 2026-11-12, asked one question at a time. Folds into §19 Server services.*

server's api answers a request whose Postgres connection a restart cut with 503 and Retry-After: 1, as it answers a lock timeout: RaiseHttpError (server/router/handler_utils.go) and the router's recover map the connection classes 08000, 08003, 08006, 57P01, 57P02 and 57P03 to 503, the cause staying in the log, so a client tells a restart from a failure that will repeat and §22.8's Postgres or PgBouncer restart row holds its retryable clause as written. A route whose effect may have committed before the cut keeps relying on its own idempotency (admin-token claims, sidecar push ids). Other internal failures keep the fixed 500.

Changes: server/router answers Postgres connection-loss classes 503 with Retry-After; TEST-M2-15's retryable half of the Postgres restart row.

Questions: `test-m2-15-postgres-restart-answer.md`.

### QD-779: Should a run card's version be the index epoch above the stream version of its run's newest entry, in place of the highest seq folded?
*Decided by the owner on 2026-11-13, asked one question at a time. Folds into §16 The local MCP server and record primitives.*

A run card's version is E * 2^32 + c: E the index_epoch its push names, which only a CUT moves, and c the stream version at which the run last gained a source entry in that stream (IndexFormatSettings.CardVersionBitCount, 32). A CUT lists a card through its epoch, so every projection made before the CUT is listed and every one made after it is above the list. This replaces RECORD.md 7.4's 'highest seq'.

Changes: DESIGN-DETAILS section 15 stands as written; SEARCH-M10-28's card version; SEARCH-M10-16's Cut takes a through-epoch document; RECORD.md 7.4 and §11.14's version row, §16.8, §16.10 text from 15.8.

Questions: `details-15-card-version.md`.

Not folded (2026-11-16): RECORD.md 7.4's version sentence and section 8's Run cards paragraph, which DESIGN-DETAILS.md 15.8 proposes, outside design/source/; the DESIGN.md parts are folded as owner decision 459 (§16.8's erasure and search bullets, §16.10's run card row, §11.12's cut row, §11.14's version, cut and erase rows).

### QD-780: Should a run have one card for each stream that holds its entries, joined at display, in place of one card a log?
*Decided by the owner on 2026-11-13, asked one question at a time. Folds into §16 The local MCP server and record primitives.*

A run card is one per run per stream: card (R, r) is the fold of what stream R holds of run r, under R's ref_id, written by R's writer in its companion push, so one push carries it and one coverage row counts it. §16.10's group row joins a run's cards by run_id: started the earliest, last activity the latest, title and fields from the card whose row time is newer.

Changes: DESIGN-DETAILS section 15 stands as written; SEARCH-M10-28's card identity and fold; SEARCH-M10-12 and -14's card markers and backfills; §16.10's documents row and RECORD.md 7.1 text from 15.8.

Questions: `details-15-card-per-stream.md`.

Not folded (2026-11-16): RECORD.md 7.1's fields row for a card, which DESIGN-DETAILS.md 15.8 proposes, outside design/source/; the DESIGN.md parts are folded as owner decision 459 (§16.8's search bullet, §16.10's documents, run card and group rows).

### QD-782: When a run's context entry is erased, may the agent label and session ids it gave the run's other entry documents stay in their index rows?
*Decided by the owner on 2026-11-13, asked one question at a time. Folds into §16 The local MCP server and record primitives.*

An erasure of a context entry lists that entry and the run's card, as §16.8 has it. Index rows of the run's other entry documents written before the erasure keep fields 9 (agent label) and 11 (session ids). From the erasure's CUT on, a builder reads those fields from the first context entry of the run that its stream holds and no erasure names; between the ERASE and the CUT a builder that holds the ERASE builds no entry document of that run. A person who wants the label or session id gone erases the run's other indexed entries too, and ur record erase says so when it lists what it will destroy.

Changes: DESIGN-DETAILS 15.2.8 stands as written; SEARCH-M10-28's reading of fields 9 and 11; ur record erase's listing text (RECORD-M10-01); §16.8 and RECORD.md 7.1 text from 15.8; taking fields 9 and 11 out of entry rows stays the sound change if this is revisited.

Questions: `details-15-context-fields.md`.

Not folded (2026-11-16): RECORD.md 7.1's fields row for an entry and ur record erase's listing in section 8, outside design/source/; the DESIGN.md part is folded as owner decision 460 (§16.8's erasure bullet).

### QD-783: Nine small readings section 15 took for index erasure and run cards: are they right?
*Decided by the owner on 2026-11-13, asked one question at a time. Folds into §16 The local MCP server and record primitives.*

Section 15's nine small readings stand as built: a reader masks a listed key at or below its listed version and applies an ERASE's whole-key mask only while no set version it holds lists the key; a record log's companion push runs on RecordSettings.CardInterval (5 min) with a build at a run's first source entry and at the coverage entry that ends it; source entries fold in (seq in their writer's chain, entry_id bytes) order; a run whose every source entry is erased has no card; a stream version or index epoch at or past 2^32 writes no card (IndexFormatSettings.CardVersionBitCount); each device that held the stream's entries when it applied the ERASE folds the card again BackfillAge after the CUT unless the index already holds it above the list; the daemon that ERASEs a copy ingested after the erasure calls the CUT again for it; the weekly BASE removes only entries whose erasure is complete; an eraser that does not mirror the log fetches at most IndexEraseSettings.CardFetchByteCount (16 MiB) a card.

Changes: DESIGN-DETAILS section 15 stands as written; RECORD.md 7.4's cadence and 8's expiry row, from 15.8's proposed text.

Questions: `details-15-small-readings.md`.

Not folded (2026-11-16): RECORD.md 7.4's cadence and section 8's expiry row, which DESIGN-DETAILS.md 15.8 proposes, outside design/source/; the DESIGN.md parts are folded as owner decision 461 (§16.8's retention bullet and §16.10's run card row).

### QD-145: `strict_chain` claims a customer-signed chain that connect's DoH path cannot show
*Accepted by the owner on 2026-11-06, in bulk as recommended; owner decision 269. Folds into §4 Repositories, code placement, branches, and build.*

Owner decision 269's table row, which waits on the code: §4.6's table gains the row `| C20 | DohCache.ForwardDnssec ... | M7 |` in the change that gives check/x9_test.go's x9Rows its C20 entry (marker `ForwardDnssec`, milestone 7, the connect task that builds it and its default-off test), since TestX9RowsAreSection46 holds the table to that ledger row for row and a design-records track writes no such entry. The rest is folded (2026-11-16): the decision, a paragraph under §4.6's table that states C20, §2.8's ext-3 (list v27), §15.5's `strict_chain` evidence, §23.4's M7 row and §4.18.

Changes: §4.6's table; check/x9_test.go x9Rows.

Questions: `plan-MAIL-dnssec-evidence.md`, `dr2-s4-c20-x9-row.md`.

### QD-024: cli/UI.md is on no path this run can read
*Accepted by the owner on 2026-11-06, in bulk as recommended; owner decision 265. Folds into §4 Repositories, code placement, branches, and build.*

Owner decision 265's file, which waits on the owner: the copy of cli/UI.md at sidecar/design/UI.md, since the sketch sits outside every repository, on no path the run reads. The rest is folded (2026-11-16): the decision and §4.11, which say the build keeps its own spellings until the copy is there.

Changes: sidecar/design/UI.md (owner step); HANDOFF section 2.

### QD-864: How does a reader of an Opening, a packet or an export line learn that its body is a version-2 AgentSignedBody?
*Decided by the owner on 2026-11-15, asked one question at a time; owner decision 466. Folds into §16 The local MCP server and record primitives.*

RECORD.md's part, which waits on RECORD.md's own change: section 5.5's `Opening` fence gains `uint32 version = 4`, which protocol/design_unfenced_test.go's `testFenceAdditions` holds until that fence writes it; section 9's jsonl export names the same answer `entry_version`; and section 11's openings read it. The rest is folded (2026-11-16): the decision and §16.8's disclosure row.

Changes: RECORD.md 5.5, 9 and 11.

Questions: `record-m6-03-opening-entry-version.md`.

### QD-899: Which source kinds give a run card the fields RECORD.md 7.4 reads from claims, coverage and approval decisions?
*Decided by the owner on 2026-11-15, asked one question at a time; owner decision 467. Folds into §16 The local MCP server and record primitives.*

RECORD.md's part, which waits on RECORD.md's own change: 7.3 and 7.4's sources row and mapping (a vault card's coverage and, in personal mode, claim and handoff; fields 13 and 14 and its row's expires; the team card's line counting approval requests), and DESIGN-DETAILS.md 15.2.2, the design agent's. The rest is folded (2026-11-16): the decision and §16.10's run card and group rows.

Changes: RECORD.md 7.3 and 7.4; DESIGN-DETAILS.md 15.2.2.

Questions: `search-m10-28-vault-card-sources.md`.

### QD-900: How does record extractor 1 find a run's user prompts, for a vault card's title fallback and its prompt text?
*Decided by the owner on 2026-11-15, asked one question at a time; owner decision 467. Folds into §16 The local MCP server and record primitives.*

RECORD.md's part, which waits on RECORD.md and record.proto: section 5's `ContextBody` gains its repeated prompts field (or the new raw kind its fix track names), which record.proto and RECORD.md's fence take together, and 7.4's prompt row reads it. The rest is folded (2026-11-16): the decision, §16.7's context row and §16.10's run card row.

Changes: RECORD.md 5's ContextBody and 7.4; record.proto.

Questions: `search-m10-28-transcript-prompts.md`.
