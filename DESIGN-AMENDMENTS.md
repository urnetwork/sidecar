# Design amendments

Every design decision made since DESIGN.md was last rebuilt and not yet folded into it, ordered by the DESIGN.md section it amends. The decisions were taken in the run's question ledger (`.stack/decisions/LEDGER.json`, ids QD-001 to QD-651), which lives outside git; this file is their durable copy in the sidecar repo.

**Precedence.** Where an item here and DESIGN.md differ, the item governs until it is folded. A complete section of DESIGN-DETAILS.md governs the tasks it names, and where an owner decision below answers one of its questions, the decision governs. Decided items are the owner's; proposed items are the agents' readings and fills, which work builds on until the owner says otherwise.

**Folding.** Only a design-records track edits `design/source/` and rebuilds DESIGN.md with `design/source/build.sh`. Each design-records track takes one DESIGN.md section, applies its items below (and the matching "Proposed DESIGN.md text" of DESIGN-DETAILS.md), and in the same commit deletes those items from this file. When this file holds no items it is deleted. Owner decisions that change behavior go into `design/source/owner/DECISIONS.md` as numbered owner decisions, after decision 197, as decision 197 was.

Holds 17 decided items and 4 proposed ones, generated from the ledger on 2026-11-10. QD-597 (owner decision 197) is already folded, and QD-336 went into §4.5 with owner decision 251 (QD-841 to QD-843), which DESIGN.md carries directly.

## Index

| DESIGN.md section | Decided | Proposed |
|---|---|---|
| [§3 Architecture overview and end-to-end flows](#s3) | 1 | 0 |
| [§5 The Sidecar core](#s5) | 2 | 1 |
| [§7 Networks, teams, members, enrollment, and SSO](#s7) | 3 | 0 |
| [§10 Group keys for evs: MLS and the GKM service](#s10) | 1 | 0 |
| [§11 Encrypted versioned storage](#s11) | 1 | 0 |
| [§15 The local email server, inbound mail, and burner email](#s15) | 1 | 0 |
| [§16 The local MCP server and record primitives](#s16) | 6 | 2 |
| [§19 Server services](#s19) | 0 | 1 |
| [No section named](#s0) | 2 | 0 |

## DESIGN-DETAILS.md sections to fold

Sections 2, 4, 5, 6, 8 and 9 of DESIGN-DETAILS.md are complete; each ends with its proposed DESIGN.md text. Their owner questions were answered on 2026-11-10 (QD-598 to QD-629, below under the sections they amend). Three answers differ from a section's recommendation and the design agent amends the section before it is folded: QD-604 (section 8, imports make helper refs), QD-621 (section 4, an overdue narrowing statement keeps the last state and alarms) and the model and wording fixes of QD-628, QD-632, QD-633, QD-642 and QD-644. Sections 1, 3, 7, 10, 11, 12 and 13 are still being written.

Sections 8 and 9's owner answers are folded as owner decisions (2026-11-10): section 9's QD-607 to QD-610, QD-612, QD-632 and QD-633 as 227-233, with QD-613 (section 6's key prefixes) as 234 and QD-640 as 235, and section 8's QD-598 to QD-606 as 236-244, each stated in §11 where it binds. Section 9 is folded whole (2026-11-17, track dr4-details-c): its proposed DESIGN.md text (9.8) as amended, the immediate due it was built on removed by owner decision 585 (QD-1046 and QD-1057, the complexity review of 2026-11-17), which reverses owner decisions 229, 414 and 569; section 14's Amendments 14-B and 14-C to its text were already carried by §11.6's object key row and §11.8's step 6. Section 8 is folded too (2026-11-17, track dr4-details-c), its proposed text (8.8) as amended, but for its prefix-rule amendments (from section 16, QD-801 and QD-803), which wait with section 16.

Section 2.8 is folded (2026-11-10): where QD-623 (owner decision 203) needed it with §2's and §3's items, and the rest with §11's, as owner decisions 225 (QD-624) and 226 (QD-625). Of the other sections' §2.8 parts, those their items name are folded: 4.8's (QD-622), 5.8's two settings (QD-629), 6.8's gkm-1 (QD-614), 9.8's evs-11 places (QD-611) and 13.8's (QD-657). 5.8's other api-7 words (tail verdicts, open proposals, the applied-id ring, confirmations) were in §2.8's block already when section 5 was folded (2026-11-17), earlier folds having written them. 8.8's evs-4 words and 9.8's evs-11 ttl went in with sections 8 and 9's fold (lists v53 and v52). 6.8's gkm-5 pointers went into §2.8's gkm-5 with §10's items (QD-618, owner decision 363).

Sections 1, 11 and 15 are folded whole (2026-11-17, track dr4-details-a): their proposed DESIGN.md text as amended, their owner answers being owner decisions 385-395 and 459-461 already, with the diff entries both sections built on removed by owner decision 584 (QD-1036, the complexity review of 2026-11-17). Their parts for protocol/INDEX-FORMAT.md and RECORD.md stay with the tracks that edit those files, and QD-779, QD-780, QD-782 and QD-783 below keep their RECORD.md parts.

Sections 2, 10 and 14 are folded whole (2026-11-17, track dr4-details-b): their proposed DESIGN.md text as amended, their owner answers being owner decisions 203, 204, 225, 226 and 501 (section 2), 396 to 398 (section 10) and 399 and 400 (section 14) already. Section 10's amendment from section 16 to §11.7's boundary row goes with section 16's fold, the prefix rules moving to Later (QD-1032). Section 14's new schedule rows wait for sidecartest/fault's catalog to take them in the same commit, since its tests hold §22.8's table to the catalog row for row, and its Amendments 14-B and 14-C, to DESIGN-DETAILS section 9's own text, went with that section's fold, which found them carried (2026-11-17, track dr4-details-c).

Sections 5 and 6 are folded (2026-11-17, track dr4-details-d): their proposed DESIGN.md text (5.8 and 6.8) as amended, their owner answers being owner decisions 205 and 262 (QD-629, QD-627) and 201, 234 and 360 to 363 (QD-614, QD-613, QD-615 to QD-618) already, and §2.8's api-7, gkm-1 and gkm-5 already holding their words. Section 5's amendments from section 16 (`AclRepo.prefix_rules`) wait with section 16. Section 6's MLS rules wait with QD-1040, which sets MLS aside for Later and which dr4-late-sweep folds with DESIGN-DEFER.md's MLS entry: the roster rule with its committer and member clauses (6.8's §10.9 rows and its D-KEYS-27), KF2's and KF5's commits, the dropped-leaf and waiting-leaf hints, D-KEYS-24's Welcome pointer clause, §10.6's note on the claim key, and the commit legs of FS-15, FS-24, FS-97 and FS-104. 6.8's D-KEYS-28, a group's one repo, is D-KEYS-27 in DESIGN.md, the next free number.

Section 4 is folded (2026-11-17, track dr4-details-d): its proposed DESIGN.md text (4.8) as amended, its owner answers being owner decisions 202, 215 and 216 (QD-622, QD-619, QD-620 with QD-621) and 487 (QD-696) already, with 485, 490 and 491's amendments, and §2.8's api-7 and gkm-1 already holding its words; `Pending.forward_delegation_id = 5` and `BridgeIdentity`'s fields 6 and 7 joined §17.8's fences, their three `testFenceAdditions` entries leaving in the same commit. FS-38's schedule now states its forwarding cases at app hosts; the M8-out case they need in its gate column and in §23.6's M8 row waits for sidecartest/fault's catalog to take it in the same commit (the forwarding schedules in sidecartest/fault/fs_bridge_forwarding_m8.go run outside the catalog until then). 4.8's lines for RESOLUTIONS.md are outside this file's folds.

Section 16 is not folded (2026-11-17, track dr4-details-c): the owner moved the client-checked prefix write rules to Later the same day (QD-1032), so none of 16.8's text goes into DESIGN.md as live design. The design-defer-doc track folds QD-1032, with DESIGN-DEFER.md's entry and the mark at section 16's head, and the prefix-rule amendments to sections 5, 8 and 10 wait with it, section 10's to §11.7's boundary row among them.

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

### QD-129: Is ur.io's OAuth consent page in scope, given owner rule 6?
*Accepted by the owner on 2026-11-06, in bulk as recommended.*

Recommend in scope: change mmm/ur.io/react/src/components/OauthConsent.jsx on mmm's `sidecar` branch to show the matching code and the one command from `authorization_details`, and add one line to HANDOFF section 5's mmm row. It is the issuer's `authorization_endpoint` and a security control, not product UI.

Changes: HANDOFF section 5; owner rule 6 (its reach).

Questions: `plan-TEAM-consent-page.md`.

Not folded (2026-11-16): the line in HANDOFF section 5's mmm row, since HANDOFF.md is outside design/source/ and so outside a design-records track's files; the decision is folded as owner decision 306, and §7.8's `page` row names the consent page's code and command.

<a id="s10"></a>
## §10 Group keys for evs: MLS and the GKM service

### QD-046: A forged reader key, beyond correcting the text
*Accepted by the owner on 2026-11-06, in bulk as recommended. Also amends §2, §5.*

[g0-recheck-0-readerkey-forgery#2] Recommended: option 2 on top of the text fix, and no post-quantum signature. Once a day, at its ReaderKey upkeep, a device GETs /gkm/reader-key/<its own id> and compares the key digest with those it signed; a key it never signed raises SidecarEvent key_changed, a kind §5.4 lists and no section yet defines, naming the foreign digest, and the remedy is §10.5's for an active clone: SidecarRevoke{reason: compromise} and a new enrollment. ReaderKey keeps the three fields landed in protocol/gkm.proto. [g0-recheck-0-readerkey-forgery#1] Correct the text, option 1. §10.5's Ladder bullet says an adversary that can forge Ed25519 and that the operator serves "could forge admissions, or a holder's ReaderKey, to which an honest rotator or hinted holder then seals RK_g with no person acting, and, through the ladder, read all retained history". Its last sentence becomes: "An external commit needs RK_g, under which the GroupInfo is sealed, so a published identity key alone commits nothing; RK_g itself rests on those signatures." §2.18's unaudited-cryptography row adds "by a forged admission or ReaderKey", and the ledger's HNDL row replaces "Nothing" with this residual. Q-KEYS-2's residual stands.

Changes: §10.5 Ladder bullet; §2.18 unaudited-cryptography row; ledger row for R3's HNDL major; §10.5 readerkey row; §5.4 key_changed; §10.15 active clone row.

Questions: `g0-recheck-0-readerkey-forgery.md#1`, `g0-recheck-0-readerkey-forgery.md#2`.

Not folded (2026-11-16): the ledger's row for R3's HNDL major, whose "Nothing" becomes this residual, since that row is in DESIGN-REVIEW-RESPONSE.md, outside design/source/ and so outside a design-records track's files; the DESIGN.md parts are folded as owner decision 358 (§10.5's Ladder and readerkey rows, §10.15's active clone row, §5.4's `key_changed`, §2.18's unaudited-cryptography row).

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

### QD-411: Q-OPS-3's residual is closed in §19.14 and open in the front matter
*Proposed reading: the agents' reading of text the design leaves open; work builds on it. Also amends §23.*

It is closed: §19.14 owns Q-OPS-3 and reads "Residual: none", and §23.6's M0 row keeps D-OPS-18's closure as a gate. Drop the Q-OPS-3 clause from PEER_INTRO (asm/data_front7.py:123-125), leaving one residual. Add "Q-OPS-3's residual" to the ledger's section 5 beside Q-QUOTA-3's, keeping Appendix B's status as decided by the owner. Copy §19.6's bound into Q-OPS-3: <= 24 h plus the run (<= 20 min) at a primary's loss, <= 26 h at the site's, a day more per skipped or aborted run; and say "the dumped sidecar rows", since tables with a ttl of at most 7 d are in no dump. The "Closed by peer review 2026-11-04" label stays, as OT-N7's own row records that marking.

Changes: front matter PEER_INTRO; ledger section 5; Q-OPS-3 text.

Questions: `g0-recheck-2-q-ops-3-records.md`.

Not folded (2026-11-16): the ledger's section 5 entry naming Q-OPS-3's residual beside Q-QUOTA-3's, since the ledger is DESIGN-REVIEW-RESPONSE.md, outside design/source/ and so outside a design-records track's files; the DESIGN.md parts are folded (the front matter's peer lead names one engineering residual, and §19.14's Q-OPS-3 carries §19.6's bound and "the dumped sidecar rows"; Appendix B's status and the "Closed by peer review 2026-11-04" label stay).

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

### QD-1005: Which kind should a restored binding's admission hold when the base that changes self_admit leaves it unfolded in its tail?
*Decided by the owner on 2026-11-16, asked one question at a time; owner decision 556. Folds into §7 Networks, teams, members, enrollment, and SSO.*

The wire and the list, which wait on the code: §7.9's `ProjectionHeader` fence takes `repeated bytes restored_cosigned_ids = 12` once auth.proto declares it, a design-records fold writing the line and dropping its `testFenceAdditions` entry in one commit (owner decision 273); and §2.8 api-7's phrase names the field, which the fix track publishes through `check/`'s additions and a design-records fold then writes into the block, the entry leaving in that commit (owner decision 252). DESIGN-DETAILS 5.2.3 and 5.2.4 are the design agent's. The rest is folded (2026-11-17): the decision, §7.9's self_admit, base and verdicts rows, and a comment in the fence naming what joins it.

Changes: §7.9's fence; §2.8 api-7; auth.proto.

Questions: `proposal-kind-restored-cosigned-tail-self-admit.md`.

Waits on: the fix track base-restored-cosigned-ids.

### QD-989: How does smtpedge learn which sidecar dialed a ur/smtpedge stream, the subject §8's mail_send is judged for, when the ur/ ticket names only the dialer's network and client?
*Decided by the owner on 2026-11-16, asked one question at a time; owner decision 560. Folds into §9 Abstract socket listeners and the scheduler.*

The wire, which waits on the code: §9.6's `SocketTicket` fence takes `bytes dialer_sidecar_id = 16` once socket.proto declares it, a design-records fold writing the line and dropping its `testFenceAdditions` entry in one commit (owner decision 273). The rest is folded (2026-11-17): the decision, §9.6's `ur/` tickets paragraph and a comment in the fence naming what joins it, §14.5's Authorization, and §2.8's sock-2 (list v45).

Changes: §9.6's fence; socket.proto.

Questions: `smtp-m9-13-dialer-sidecar.md`.

Waits on: the fix track ur-ticket-dialer-sidecar.

### QD-1013: How does sockets check a team member's Client-class token, which carries member_id and which the revocation record keeps no state for, with no SQL?
*Decided by the owner on 2026-11-17, asked one question at a time; owner decision 561. Folds into §9 Abstract socket listeners and the scheduler.*

The list and the test, which wait: §2.8's row for the revocation record's family gains member and user ids (I-18), and an FS case covers a membership's removal racing a projection. §2.8 holds no row for that family, `{rv_<network_id>_<k>}` (server/session/REVOKE-FINAL.md), so the words have no row to join. QD-1022 (owner, 2026-11-17; question `dr3-s7-s10-revocation-record-row.md`) has a design-records fold add one, api-16 or the next free api id, with its `planned` line, once the fix track revocation-record-members has settled the record's exact field forms: the fix track revocation-record-row, run in the design-records lane, that track's addition to a row that does not exist dropped. The FS case is the fix track's, and a §22.8 row for it, if it takes one, lands with sidecartest/fault's catalog, which holds §22.8's table row for row. The rest is folded (2026-11-17): the decision, §9.8's client tokens, §7.5's members and §19.10's Postgres row.

Changes: §2.8; §22.8.

Questions: `sock-client-verifier-member-credentials.md`, `dr3-s7-s10-revocation-record-row.md`.

Waits on: the fix track revocation-record-members, then the fix track revocation-record-row (QD-1022).

### QD-1010: How does an app approve a multi-use template request, when SidecarApprovals.Decide carries no uses?
*Decided by the owner on 2026-11-16, asked one question at a time; owner decision 574. Folds into §16 The local MCP server and record primitives.*

The wire, which waits on the code: §16.8's `ApprovalRequest` fence takes the field holding the uses an agent requests for a template once record.proto declares it, with the version bump RECORD.md's rules give a format change after M3's freeze, a design-records fold writing the line and dropping its `testFenceAdditions` entry in one commit (owner decision 273). The rest is folded (2026-11-17): the decision, §16.6's multi-use row, §18.5's `Decide` and a comment in the fence naming what joins it.

Changes: §16.8's fence; record.proto.

Questions: `mcp-m8-01-app-template-uses.md`.

Waits on: the fix track approval-request-uses.
