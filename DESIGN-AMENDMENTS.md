# Design amendments

Every design decision made since DESIGN.md was last rebuilt and not yet folded into it, ordered by the DESIGN.md section it amends. The decisions were taken in the run's question ledger (`.stack/decisions/LEDGER.json`, ids QD-001 to QD-651), which lives outside git; this file is their durable copy in the sidecar repo.

**Precedence.** Where an item here and DESIGN.md differ, the item governs until it is folded. A complete section of DESIGN-DETAILS.md governs the tasks it names, and where an owner decision below answers one of its questions, the decision governs. Decided items are the owner's; proposed items are the agents' readings and fills, which work builds on until the owner says otherwise.

**Folding.** Only a design-records track edits `design/source/` and rebuilds DESIGN.md with `design/source/build.sh`. Each design-records track takes one DESIGN.md section, applies its items below (and the matching "Proposed DESIGN.md text" of DESIGN-DETAILS.md), and in the same commit deletes those items from this file. When this file holds no items it is deleted. Owner decisions that change behavior go into `design/source/owner/DECISIONS.md` as numbered owner decisions, after decision 197, as decision 197 was.

Generated from the ledger on 2026-11-10, it holds no item under a DESIGN.md section now: the last were folded on 2026-11-18 by track dr4-outside-docs, their parts in RECORD.md, the review ledger, pitch5.html and HANDOFF.md with them. "Later decisions", below, holds five items: two wait on a file outside the design-records tracks' reach, and three are what track dr6-late-sweep left of the answers it folded on 2026-11-19 as owner decisions 617 to 636, each waiting on HANDOFF.md, on KEYS's review-phase rework or on a field the code does not declare yet. The fourth late sweep, track dr7-late-sweep, folded owner decisions 638 to 646 and two fixes the same day and left nothing of them here. QD-597 (owner decision 197) is already folded, and QD-336 went into §4.5 with owner decision 251 (QD-841 to QD-843), which DESIGN.md carries directly.

## Index

No section holds an item. "Later decisions" holds QD-024 (§4), QD-899 (§16), QD-1083 (§6), QD-1086 (§22) and QD-1096 (§7).

## DESIGN-DETAILS.md sections to fold

Sections 2, 4, 5, 6, 8 and 9 of DESIGN-DETAILS.md are complete; each ends with its proposed DESIGN.md text. Their owner questions were answered on 2026-11-10 (QD-598 to QD-629, below under the sections they amend). Three answers differ from a section's recommendation and the design agent amends the section before it is folded: QD-604 (section 8, imports make helper refs), QD-621 (section 4, an overdue narrowing statement keeps the last state and alarms) and the model and wording fixes of QD-628, QD-632, QD-633, QD-642 and QD-644. Sections 1, 3, 7, 10, 11, 12 and 13 are still being written.

Sections 8 and 9's owner answers are folded as owner decisions (2026-11-10): section 9's QD-607 to QD-610, QD-612, QD-632 and QD-633 as 227-233, with QD-613 (section 6's key prefixes) as 234 and QD-640 as 235, and section 8's QD-598 to QD-606 as 236-244, each stated in §11 where it binds. Section 9 is folded whole (2026-11-17, track dr4-details-c): its proposed DESIGN.md text (9.8) as amended, the immediate due it was built on removed by owner decision 585 (QD-1046 and QD-1057, the complexity review of 2026-11-17), which reverses owner decisions 229, 414 and 569; section 14's Amendments 14-B and 14-C to its text were already carried by §11.6's object key row and §11.8's step 6. Section 8 is folded too (2026-11-17, track dr4-details-c), its proposed text (8.8) as amended, but for its prefix-rule amendments (from section 16, QD-801 and QD-803), which wait with section 16.

Section 2.8 is folded (2026-11-10): where QD-623 (owner decision 203) needed it with §2's and §3's items, and the rest with §11's, as owner decisions 225 (QD-624) and 226 (QD-625). Of the other sections' §2.8 parts, those their items name are folded: 4.8's (QD-622), 5.8's two settings (QD-629), 6.8's gkm-1 (QD-614), 9.8's evs-11 places (QD-611) and 13.8's (QD-657). 5.8's other api-7 words (tail verdicts, open proposals, the applied-id ring, confirmations) were in §2.8's block already when section 5 was folded (2026-11-17), earlier folds having written them. 8.8's evs-4 words and 9.8's evs-11 ttl went in with sections 8 and 9's fold (lists v53 and v52). 6.8's gkm-5 pointers went into §2.8's gkm-5 with §10's items (QD-618, owner decision 363).

Sections 1, 11 and 15 are folded whole (2026-11-17, track dr4-details-a): their proposed DESIGN.md text as amended, their owner answers being owner decisions 385-395 and 459-461 already, with the diff entries both sections built on removed by owner decision 584 (QD-1036, the complexity review of 2026-11-17). Their parts for protocol/INDEX-FORMAT.md stay with the tracks that edit it; section 15's part for RECORD.md, the only one of the three that has one, is folded with QD-779, QD-780, QD-782 and QD-783 (2026-11-18, track dr4-outside-docs).

Sections 2, 10 and 14 are folded whole (2026-11-17, track dr4-details-b): their proposed DESIGN.md text as amended, their owner answers being owner decisions 203, 204, 225, 226 and 501 (section 2), 396 to 398 (section 10) and 399 and 400 (section 14) already. Section 10's amendment from section 16 to §11.7's boundary row goes with section 16's fold, the prefix rules moving to Later (QD-1032). Section 14's new schedule rows wait for sidecartest/fault's catalog to take them in the same commit, since its tests hold §22.8's table to the catalog row for row, and its Amendments 14-B and 14-C, to DESIGN-DETAILS section 9's own text, went with that section's fold, which found them carried (2026-11-17, track dr4-details-c).

Sections 5 and 6 are folded (2026-11-17, track dr4-details-d): their proposed DESIGN.md text (5.8 and 6.8) as amended, their owner answers being owner decisions 205 and 262 (QD-629, QD-627) and 201, 234 and 360 to 363 (QD-614, QD-613, QD-615 to QD-618) already, and §2.8's api-7, gkm-1 and gkm-5 already holding their words. Section 5's amendments from section 16 (`AclRepo.prefix_rules`) wait with section 16. Section 6's MLS rules went with QD-1040, which sets MLS aside for Later, folded by track dr4-late-sweep (2026-11-18) as owner decision 610: DESIGN-DEFER.md's keys-mls entry lists them as what returns with MLS, the roster rule with its committer and member clauses (6.8's §10.9 rows and its D-KEYS-27), KF2's and KF5's commits, the dropped-leaf and waiting-leaf hints, D-KEYS-24's Welcome pointer clause, §10.6's note on the claim key, and the commit legs of FS-15, FS-24, FS-97 and FS-104, and none of them enters DESIGN.md as live design. 6.8's D-KEYS-28, a group's one repo, is D-KEYS-27 in DESIGN.md, the next free number.

Section 4 is folded (2026-11-17, track dr4-details-d): its proposed DESIGN.md text (4.8) as amended, its owner answers being owner decisions 202, 215 and 216 (QD-622, QD-619, QD-620 with QD-621) and 487 (QD-696) already, with 485, 490 and 491's amendments, and §2.8's api-7 and gkm-1 already holding its words; `Pending.forward_delegation_id = 5` and `BridgeIdentity`'s fields 6 and 7 joined §17.8's fences, their three `testFenceAdditions` entries leaving in the same commit. FS-38's schedule now states its forwarding cases at app hosts; the M8-out case they need in its gate column and in §23.6's M8 row waits for sidecartest/fault's catalog to take it in the same commit (the forwarding schedules in sidecartest/fault/fs_bridge_forwarding_m8.go run outside the catalog until then). 4.8's lines for RESOLUTIONS.md are outside this file's folds.

Sections 3, 13 and 17 are folded (2026-11-17, track dr4-details-e): their proposed DESIGN.md text (3.8, 13.8 and 17.8) as amended, their owner answers being owner decisions 253, 266 and 433 to 435 (section 3), 337, 338 and 516 to 518 (section 13) and 424 to 427 and 571 (section 17) already, and §2.8's smtp-2, smtp-7, sock-1 to sock-4, api-8, api-13, cert-1 and cert-2 already holding their words. Section 17's eleven schedules (17.6) are stated in §22.5's §13 row and wait, as numbered rows of §22.8's table, for sidecartest/fault's catalog to take them in the same commit. 17.2.8's A10 and two-window replay stay the design agent's open item in DESIGN-DETAILS.md: DESIGN.md carries owner decision 571's quiet-window replay and 16 d of spends (QD-994, QD-996). Section 3's readings and its SPEC.md draft belong to smtpproof/SPEC.md.

Section 7 is folded (2026-11-18, track dr4-details-e): its proposed DESIGN.md text (7.8) as amended, its owner answers being owner decisions 391 to 393 (QD-707 to QD-711) already, with owner decision 450 (QD-048) for the hints. Not folded, because QD-1038 (owner, 2026-11-17) removes the keep-warm pairs, the bit-1 marking and C19's window accounting: the three warm pairs of §6.10's and §18.7's foreground rows, `MarkedPeerMaxCount` and `Search.RemoteOtherWarmCount`, §18.4's cost of a second and third pair's floor, D-SDK-27's third pair and FS-83's clause on no contract opening at a search. Track dr4-late-sweep folded QD-1038 as owner decision 609 (2026-11-18): the rows that owner decisions 188, 191 and 391 gave warm pairs and windows lose them, so none of these enters DESIGN.md.

Section 12 is folded (2026-11-17, track dr4-details-d): its proposed DESIGN.md text (12.8) as amended for QD-761, its owner answers being owner decisions 473 to 478 and 483 already, and §17.9's fences already holding its share pins and seal bodies (track dr4-fences).

Section 16 is not folded (2026-11-17, track dr4-details-c): the owner moved the client-checked prefix write rules to Later the same day (QD-1032), so none of 16.8's text goes into DESIGN.md as live design. The design-defer-doc track folded QD-1032 as owner decision 586 (2026-11-18): DESIGN.md says the rules are Later where it describes them (§8.8, §8.12, D-ACL-11, §8.19, §11.8's refusals row, §11.11's prefix and new refs rows, D-EVS-18, Q-EVS-3, §11.22, §23.4), DESIGN-DEFER.md's entry "Client-checked prefix write rules" documents the deferral, and section 16 carries the mark at its head. Not folded, waiting with the rules: section 16's proposed text (16.8) and its prefix-rule amendments to sections 5, 8 and 10, section 10's to §11.7's boundary row among them; a reversal of owner decision 586 folds them. The same track folded QD-1033 as owner decision 587: DESIGN-DEFER.md, generated from `design/source/defer/` by `design/source/build.sh`, documents every deferred decision, one entry each, and each section a deferral touches points at its entry.

<a id="later"></a>
## Later decisions

Decisions taken after this file was generated, each naming the section it folds into. A design-records track folds the ones that name its sections, with that section's items above, and deletes them here.

§2.8's block holds the published list whole since 2026-11-16 (v26): the track for §2 and §3 wrote into it every line that items here and above had added to metadata_list.yml ahead of a fold through check's additions, list versions v12 to v25 (QD-040, QD-720, QD-724, QD-725, QD-743, QD-746, QD-763, QD-764, QD-765, QD-798, QD-819, QD-828, QD-830, QD-840 and DESIGN-DETAILS 17.2.16), and check's additions list is empty. Those items' §2.8 words are therefore done; their other parts fold with their sections, and a later row change is written in the block and copied by `make metadata`. The §10 fold wrote QD-857's v31 lines (cert-1's name failure backoff), which check's additions had published, into the block the same way on 2026-11-16, its entries leaving check's list, and took v32 for itself; QD-857's §13 parts were folded with §13 (owner decision 430). The §11 fold wrote QD-199's smtp-4 words, which SMTP-M9-16 had published through check's additions, into the block the same way, in the list's v34, after its own v33; QD-199's §14 and §20 parts were folded with §14.

### QD-024: cli/UI.md is on no path this run can read
*Accepted by the owner on 2026-11-06, in bulk as recommended; owner decision 265. Folds into §4 Repositories, code placement, branches, and build.*

Owner decision 265's file, which waits on the owner: the copy of cli/UI.md at sidecar/design/UI.md, since the sketch sits outside every repository, on no path the run reads. The rest is folded (2026-11-16): the decision and §4.11, which say the build keeps its own spellings until the copy is there.

Changes: sidecar/design/UI.md (owner step); HANDOFF section 2.

Not folded (2026-11-18): sidecar/design/UI.md is still absent, and the copy is the owner's step; HANDOFF.md is outside design/source/.

Not folded (2026-11-18, track dr4-outside-docs): sidecar/design/UI.md is still absent, and HANDOFF section 2's line would name that copy, so it waits with it.

Not folded (2026-11-19, track dr6-late-sweep): sidecar/design/UI.md is still absent; the copy is the owner's step.

Not folded (2026-11-19, track dr7-late-sweep): sidecar/design/UI.md is still absent; the copy is the owner's step at the review handoff.

### QD-899: Which source kinds give a run card the fields RECORD.md 7.4 reads from claims, coverage and approval decisions?
*Decided by the owner on 2026-11-15, asked one question at a time; owner decision 467. Folds into §16 The local MCP server and record primitives.*

RECORD.md's part, which waits on RECORD.md's own change: 7.3 and 7.4's sources row and mapping (a vault card's coverage and, in personal mode, claim and handoff; fields 13 and 14 and its row's expires; the team card's line counting approval requests), and DESIGN-DETAILS.md 15.2.2, the design agent's. The rest is folded (2026-11-16): the decision and §16.10's run card and group rows.

Changes: RECORD.md 7.3 and 7.4; DESIGN-DETAILS.md 15.2.2.

Questions: `search-m10-28-vault-card-sources.md`.

Not folded (2026-11-18): RECORD.md 7.3 and 7.4, outside design/source/, and DESIGN-DETAILS.md 15.2.2, the design agent's.

Not folded (2026-11-18, track dr4-outside-docs): DESIGN-DETAILS.md 15.2.2's source entry, which still names a vault's sources without coverage, claim and handoff, the design agent's to amend; RECORD.md 7.3 and 7.4 are folded (the vault card's sources, fields 13 and 14 and its row's expires, and the team card's line of action kinds asked for approval).

Not folded (2026-11-19, track dr6-late-sweep): DESIGN-DETAILS.md 15.2.2 is unchanged, and it is the design agent's.

Not folded (2026-11-19, track dr7-late-sweep): DESIGN-DETAILS.md 15.2.2's source entry still lists a vault's sources without coverage, claim and handoff, and it is the design agent's.

### QD-1083: Should design-records drop the two places DESIGN.md still describes C19 as live, §6.10's opening debit list and §23.9's merge rule?
*Decided by the owner on 2026-11-18, asked one question at a time. Folds into §6 The sidecar subprotocol.*

HANDOFF.md's part, which waits on a track that edits HANDOFF.md: section 9's two lines that still name FS-125's C19 windows and its sweep in connect's tests before connect's `main` merge, which owner decision 609 reversed. The rest is folded (2026-11-19): §6.10's first paragraph no longer debits a marked remote-search pair at C19's floor, and §23.9 item 2 no longer makes connect's merge wait on FS-125's sweep. FS-125's catalog row and its §23.6 and §22.17 naming stay, as track dr4-late-sweep left them on purpose.

Changes: HANDOFF.md section 9's two FS-125 lines.

Questions: `c19-windows-removed-design-leftovers.md`.

Not folded (2026-11-19, track dr6-late-sweep): HANDOFF.md is outside this track's files; the final design sweep's list holds the two lines.

Not folded (2026-11-19, track dr7-late-sweep): HANDOFF.md is outside this track's files, and its brief leaves HANDOFF.md's lines to the final design sweep. A third place in DESIGN.md that still described C19's windows as live, §6.16's Interfaces, is folded: its Provides and Assumptions follow owner decision 609.

### QD-1086: How should M2's gate show FS-15, FS-20, FS-24 and FS-104, whose MLS legs owner decision 610 took off the gates?
*Decided by the owner on 2026-11-18, asked one question at a time; owner decision 627. Folds into §22 Testing and verification.*

The fold of owner decision 610 that this answer puts with KEYS's review-phase rework: §22.8's FS-15, FS-20, FS-24 and FS-104 rows, §22.10's table, §23.6's M2 row, §23.8's freezes and D-KEYS-10 still put the MLS legs and the 0x0010 interop at M2's exit, and sidecartest/fault's catalog.yml is held to §22.8's text. The rest is folded (2026-11-19): owner decision 627, §23.8's Freezes line, which says the MLS legs count toward nothing at M2 and that the four rows run their drafted schedules meanwhile, and DESIGN-DEFER.md's keys-mls entry, whose Held field lists this fold.

Changes: §22.8's four rows, §22.10's table, §23.6's M2 row, §23.8's freezes and D-KEYS-10, with sidecartest/fault/catalog.yml in the same commit.

Questions: `test-m2-19-mls-legs-at-m2.md`.

Not folded (2026-11-19, track dr6-late-sweep): KEYS's review-phase rework of the four rows onto deliveries has not landed, and the catalog's tests hold §22.8's table row for row.

Not folded (2026-11-19, track dr7-late-sweep): the rework is review-phase work and has not landed; the four rows keep their drafted schedules.

### QD-1096: Should IndexerRow and ConfigIndexer carry the IndexerSet header's nonce, so any reader can open a designation's sealed services after a fold?
*Decided by the owner on 2026-11-19, asked one question at a time; owner decision 634. Folds into §7 Networks, teams, members, enrollment, and SSO.*

The wire part, which waits on the code: `IndexerRow`'s `bytes nonce = 6` in §7.9's proto fence, which protocol's fence test holds to protocol/bridge/auth.proto, and auth.proto does not declare the field yet (fix track indexer-row-nonce). The fence carries a comment naming the decision. The rest is folded (2026-11-19): owner decision 634, §7.9's Indexers paragraph and §2.8's api-7, list v61.

Changes: §7.9's `IndexerRow` fence, with the field's `testFenceAdditions` entry leaving protocol/design_unfenced_test.go in the same commit if the fix track adds one.

Questions: `mail-m8-10-indexer-services-seal-context.md`.

Not folded (2026-11-19, track dr6-late-sweep): auth.proto declares no `IndexerRow.nonce`, and a fence never moves ahead of the code (owner decision 273).

Not folded (2026-11-19, track dr7-late-sweep): auth.proto's `IndexerRow` still declares fields 1 to 5 and no nonce, so the fence stays as the code is.
