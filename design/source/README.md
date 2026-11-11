# DESIGN.md sources

[DESIGN.md](../../DESIGN.md) is generated. This folder holds what it is built from: the 23 section files, the owner's decision record, the conventions the design was written under, and the scripts that assemble and validate it. They came from the design sessions' working folder on 2026-11-06. From then on this folder is the source of truth. Edit here and rebuild; never edit DESIGN.md by hand, since the next build overwrites it.

## Contents

| Path | What it is |
|---|---|
| `sections/01-CTX.md` … `sections/23-PHASE.md` | DESIGN.md §1-§23, one file per section. The build copies them verbatim, adding only links. |
| `owner/DECISIONS.md` | The owner's record, entries 1-250. Each entry gives the question, the answer, what it costs and the options not taken. "Owner decision N" in DESIGN.md cites entry N. The file ends with owner instructions that carry no number. |
| `owner/APPLY.md` | The rules for applying the owner's decisions: precedence (§1), supersession, where two decisions disagree (§2), notation (§3), editing rules (§4), and the follow-up decisions 112-136 with the sections each binds (§6-§8). |
| `CONVENTIONS.md` | The writing conventions every section follows: the owner directive (§0), the owner rules (§1), the section template (§2) and the X registry (§7), which DESIGN.md's X1-X20 table replaced. |
| `OUTLINE.md` | The original outline: section codes, scope boundaries, and the word budgets that G0's density rule replaced on 2026-11-04. |
| `asm/` | The assembler, the validator and their data (below). |
| `build.sh` | Rebuilds DESIGN.md and validates it. |

## Build

```sh
design/source/build.sh                  # rebuild DESIGN.md at the repo root, then validate it
design/source/build.sh /tmp/DESIGN.md   # build elsewhere, to check a change without touching DESIGN.md
```

It needs only `python3`; it was built and checked with Python 3.13. The steps, all run from `asm/`:

1. `extract.py` parses the section files into `v7/extract.json`: ids, items and questions.
2. `fields.py` pulls each question's fields into `v7/qfields.json`.
3. `cites10.py` maps every owner decision to the sections that cite it, in `v7/cites.json`.
4. `assemble10.py` writes DESIGN.md: the front matter, the owner decisions by number, the contents, §1-§23, and Appendices A-H.
5. `validate10.py` writes `v7/validate.json`, with a summary in `v7/validate_stdout.txt`.

`v7/` is the working-directory name the scripts expect; the name is historical. Every file the build writes is git-ignored.

## Where DESIGN.md's generated parts come from

| Part | Source |
|---|---|
| Status line, owner directive, owner rules, branch policy, how to review, owner decisions by number | `asm/data_front10.py` |
| Appendix A (decisions) and Appendix B (questions) | the sections' D- and Q- items, with summaries from `asm/data_registers10.py`, `v10reg.json` and `v10/qstatus_final.json` |
| Appendix C (glossary) | `asm/data_glossary10.py` and `v10glossary.json`. The cap is 5,250 words, and the glossary is at it. |
| Appendices D-H | `asm/data_appx10.py` and the section text |

The data files are layered. Each `data_*N.py` loads its predecessor with `runpy` and patches it: `data_front10.py` loads `data_front9.py`, back to `data_front3.py`, and the registers, glossary and appendices go the same way. Change the top layer (the `*10` files), or add an `*11` layer that loads them. Comments in the scripts cite working files from the design sessions (the reconcilers' orders, `peer/`, `review/`, `snap/`), which were not imported; they are history.

## Adding owner decision N (251 onward)

1. Add entry N to `owner/DECISIONS.md`: the question, the answer, its cost, the options not taken, and what raised it.
2. In `asm/data_front10.py`, append `(N, "<what it settles>", "<one line>")` to `INDEX`, add `DATES[N]`, and raise the `assert` to `list(range(1, N + 1))`. Update `STATUS` and `DECISIONS_INTRO` where they name a range. `@@OD:k@@` writes a link to decision k.
3. Set `MAXD = N` in `asm/assemble10.py` and `asm/cites10.py`.
4. In `asm/validate10.py`, raise both `list(range(1, N))` checks, `owner_record` and `decision_rows`, to `N + 1`, and add N's date to `LATE_DATES`, which `dates_ok` reads from 198 on, since the build's answers are numbered as they are folded and a later number can carry an earlier day (2026-11-06's bulk acceptance). A day no earlier entry has also needs `decision_rows`' date pattern, as 2026-11-10 was added for decision 198.
5. In the sections, mark the question "**Decided by owner YYYY-MM-DD (owner decision N):**", or "**Amended by owner …**" for a change to an earlier answer; `assemble10.py`'s `DECIDED` and `AMENDED` patterns read the date from that mark for Appendix B's status cell. Cite "owner decision N" in every section that implements it: the validator fails any decision that no section cites. That is D-ARCH-4's assembly check, which G0 requires (§23.8).
6. If the question's status cell changes, update it in `asm/v10/qstatus_final.json`.
7. Rebuild, and read `v7/validate.json`.

## The validator's hand-maintained inputs

`validate10.py` also reads three files that no build step regenerates:

- `v7/words.json` holds words per section against the OUTLINE ceilings, which G0's density rule replaced. It is informational. Regenerate it with `python3 -I wordcount2.py .. v7/words.json`, run from `asm/`.
- `v7/text_checks.json` lists reviewer ids, bare `<placeholders>` and HTML tags outside code, all of which break rendering or leak working ids. Regenerate it with `python3 -I text_checks6.py .. v7/text_checks.json`, run from `asm/`.
- `v7/hits_class.json` holds a heuristic grep for superseded options (`v7/supersede_grep7.py`, whose docstring lists each family and the owner decision it guards), plus a hand reading of every hit. A hit on a new or changed line has no reading until someone reads it against the owner's record. Before a review gate, rerun the grep with `python3 -I v7/supersede_grep7.py .. /tmp/hits.json` and read the new hits.

## Validation after owner decisions 192-196 (2026-11-06)

`build.sh` on this folder reproduces DESIGN.md (SHA-256 `41ec31ec017eaf3ac306497c0fe8806f895adf22e2ad72e237bcc8df5c082661`). All three hand-maintained inputs were regenerated for these sections that day. The validation shows:

- **Ids.** None duplicated, undefined, or outside its own section.
- **Links.** Every internal, relative and research link resolves. One section reference stays unresolved by design: RFC 5246's §7.4.9, inside a code block.
- **Owner decisions.** All 196 rows are present, and the sections cite each one: D-ARCH-4's check.
- **Sections.** Each of §1-§23 in DESIGN.md matches its file.
- **Superseded options.** All 292 grep hits have a reading. None is live, and none contradicts another section. Four are marked stated: text that openly revises owner decision 145's sizing figures, as its corrected record does.
- **Text.** No bare placeholders or HTML tags. One id follows a research link (`[R:ext-edge] §5 R8`); it names an item in that sheet, which the conventions allow.

The import changed two things in the tooling:

- `validate10.py` accepts the research root `design/design-research/`. Until then it flagged every `[R:key]` link as broken, and every section holding one as a verbatim mismatch, because the sheets moved there on 2026-11-05.
- `v7/carry_readings.py` was added. It carries the readings forward to a fresh grep, so only new hits need reading.

## Validation after owner decision 197 (2026-11-09)

`build.sh` on this folder reproduces DESIGN.md (SHA-256 `97b88431ef4579c8342a8c7fa6a6d9a6f85a2c71651e78e0015fb98fe1fd7177`). Owner decision 197 put only IP and port forwarding in every app's VPN component and ran Android's sidecar only while the app is open; its design touched §1-§8, §10-§12, §15, §17-§20, §22 and §23, all of which cite it. A second pass the same day carried it into lines the first had left: §4.4's leg sentence, the site-loss and missed-code risks of §2.18, §11.13, §15.16 and §23.15, which now name phone-only users on iOS or Android, the device-role names left in §7.16, §17.16 and §18.14, and `EnableBridge`'s place as a release gate (§17.16). The validation shows:

- **Ids.** None duplicated, undefined, or outside its own section: two new D- items (D-TEAM-33, D-SDK-32) and two new Q- items, each with its register summary.
- **Links.** As before: every internal, relative and research link resolves, with RFC 5246's §7.4.9 the one unresolved section reference.
- **Owner decisions.** All 197 rows are present and cited. Rows 12 and 87 note decision 197's amendment, as row 176 notes 188's (`data_front10.py`).
- **Open owner questions.** Two, Q-BRIDGE-8 and Q-SDK-7, raised in designing decision 197: the front matter's table lists them, §23.6 places them, and the sections are written to each recommendation, marked "(proposed; Q-...)". `data_front7.py`'s check, which required none open, now allows these two and no other.
- **Superseded options.** 301 grep hits, each with a reading; 14 were read on 2026-11-09 (the open questions' recommendation markers and decider lines, three settled items named by their answers, and §1's line now naming the open questions). None is live. The second pass's grep, carried forward, found no new hit.
- **Text.** No bare placeholders or HTML tags; the one research-sheet id stands. `v7/words.json` and `v7/text_checks.json` were regenerated after the second pass.
- **The metadata list** is v9 (api-4's `forward_only`, api-7's forwarding Delegations, connect-1's forwarding-key delegations), copied to `metadata_list.yml` by `make metadata`.

The tooling changed in two places: `validate10.py`'s `decision_rows` takes the 2026-11-09 date, and `data_front7.py`'s open-question check allows the two questions above. Tests outside this folder read the sections too: `sidecartest/fault`'s catalog mirrors §22.8's FS gates and §23.6's gate map, `check/`'s conformance ledger pins §22.9's peers, and `sidecartest`'s privacy and bounds tests read §22.7 and §22.8, so a change to those lines lands with the code that mirrors it.

## Validation after the build's answers, owner decisions 198-214 (2026-11-10)

The design-records track for §2 and §3 folded those sections' items from sidecar/DESIGN-AMENDMENTS.md. The owner's answers that change a behavior or a rule became owner decisions 198-214, each citing its ledger id: those decided one at a time on 2026-11-10 (198-206), and the owner-class items the owner accepted in bulk on 2026-11-06 (207-214), numbered as they were folded. Accepted defect fixes, readings and fills went in as text; QD-004's fold, which reserves AclTarget's CIDR and AclRule's ports in §8.8's fence, landed with acl.proto's matching change, since protocol's fence test holds the two together. Decision 213 also asked for a Q- item on `apt upgrade`, which waits on §4's evidence matrix in check/ (sidecar/DESIGN-AMENDMENTS.md, QD-023). A later pass the same day carried owner decision 203 into §2.8's evs-3 and §11's matching line: taskworker raises evacuation fences only, so fence_ms is evacuation's time, and a ref fenced before its first commit holds a placeholder head with its fence. `build.sh` on this folder reproduced DESIGN.md (SHA-256 `9bb6affd5921caa05a534cf3eb2e169767cd05a0d70647a7aaea935bc1a31495`) at that track's last fold, and the validation shows:

- **Ids.** None duplicated, undefined, or outside its own section; no new D- or Q- item.
- **Owner decisions.** All 214 rows are present and cited; row 183 notes decision 204's amendment of its 25-minute fence. `validate10.py`'s `LATE_DATES` gives each row from 198 its date.
- **Superseded options.** 302 grep hits, each with a reading; those on changed lines were read on 2026-11-10. None is live.
- **Text.** No bare placeholders or HTML tags; the one research-sheet id stands.
- **The metadata list** is v10, whose header names what it adds, copied to `metadata_list.yml` by `make metadata`. Two new rows the owner asked for, ext rows for Cloudflare at https://ur.io and for the abuse mailboxes' provider, wait on question `dr-s2-s3-new-metadata-rows.md`, since §22.7's guard needs each new row's `planned` line in `testdata/metadata/fields.yml` in the same commit; QD-206's row for the file clusters' bookkeeping went into evs-10, the file cluster's own row.

## Validation after owner decisions 215-224 (2026-11-10)

The design-records track for §17 and §18 folded those sections' items from sidecar/DESIGN-AMENDMENTS.md. The owner's answers that change a behavior or a rule became owner decisions 215-224, each citing its ledger id: those decided one at a time on 2026-11-10 (215-218: forwarding's iOS executable budget and compile cap, which decide Q-SDK-7, the key origin's per-network databases and multi-use bridge approvals), the key origin's sign-in hand-off the owner chose on 2026-11-06 (219), and the owner-class items accepted in bulk that day (220-224: requested grants' sealed detail, promoted key-origin builds, wintun.dll left unbundled, the ur.io/recurd page and C16's latch). Accepted defect fixes, readings and fills went in as text, among them the share seal and share pins (§17.9), the hook's modes, contract class, setter and binder (§17.6), the sign-out edge (§17.8, §18.6), the foreground report (§5.4, §18.5, §18.7) and the key origin's CSP and storage (§18.8); the parts they name in §2.8's EX7, §4.6, §4.7, §4.10, §5.4, §7.8, §7.9, §8.8, §8.11, §8.17, §13.7, §13.17, §16.8, §22.5, §22.8 (FS-37, FS-38, FS-56), §22.9 and §23 went in with them. Two items fell to owner decision 197, which replaced the keyless device role before they were folded: the window clients the sidecar role would have minted for it (QD-184) and the BridgeState chunks it would have taken over the device RPC (QD-559). Three wire parts wait in DESIGN-AMENDMENTS.md's "Later decisions", since protocol's fence test holds each fence to its .proto: CanonicalAction's `sealed_detail` (decision 220) with §2.8's api-7 and api-10, `BridgeShareGrant` for §17.9's fence, and `Pending`'s two sign-out fields, which bridge.proto declares and the test's additions list holds (question `dr-s17-s18-fence-additions.md`); each fence carries a comment naming what joins it. `build.sh` on this folder reproduced DESIGN.md (SHA-256 `108fad99b1c3f4de8cdc2b8225c7404ec7928a63deb7f80c7c168e6d233900e5`) at this fold, and the validation shows:

- **Ids.** None duplicated, undefined, or outside its own section; no new D-, Q- or FS- item.
- **Owner decisions.** All 224 rows are present and cited. Q-SDK-7 is decided, so the front matter lists one open owner question, Q-BRIDGE-8, and `data_front10.py`'s `OPEN_OWNER` holds it alone.
- **Superseded options.** 294 grep hits, each with a reading: the eight on Q-SDK-7's "(proposed; ...)" markers and decider line went with them, and the one on §17.17's changed risk row was read on 2026-11-10. None is live.
- **Text.** No bare placeholders or HTML tags; the one research-sheet id stands. `v7/words.json` and `v7/text_checks.json` were regenerated.
- **The metadata list** is unchanged (v10): §2.8's only change is EX7's prose, outside the list.

The tooling changed in one place: `assemble10.py`'s `DECIDED` and `AMENDED` patterns read a 2026-11-1x date, since Q-SDK-7 is the first Q- item decided after 2026-11-09, and Appendix B's status cell otherwise lost its decision numbers.

## Validation after owner decisions 225 onward: §11's items (2026-11-10)

The design-records track for §11 folds that section's items from sidecar/DESIGN-AMENDMENTS.md in pieces, each landed on its own, and the owner's answers that change a behavior or a rule become owner decisions 225 onward, each citing its ledger id.

- **First piece.** It finishes DESIGN-DETAILS.md section 2.8 (segment GC and the store's settle rules), whose QD-623 part went in with §2's fold: owner decisions 225 and 226 (QD-624 and QD-625) give the in-house MinIO build a DELETE that names its object's LastModified and a LIST answered only when it is whole, and §11.3, §11.8's step 6, §11.13's needs and orphans rows, §19.6's settle, list and clocks rows, §19.10's held-key row, D-OPS-20, §19.17's risk rows, §22.8's StoreSettle.tla row, FI-30, FS-114 and §22.9's file-cluster list take section 2.8's remaining words, with QD-254's (no lifecycle rule on any bucket). FS-59's checks column stays FI-6 until sidecartest/fault/catalog.yml takes FI-1,6 with it.
- **Second piece.** DESIGN-DETAILS.md sections 8 and 9's owner answers, without their proposed text, which waits for the design agent's amendments: 227-233 (QD-607 to QD-610, QD-612, QD-632, QD-633: a fold's source deletes, a map's source below the window, the crossing creation refused, the copy's map check, the root directory, a new ref's epoch, inline leaf places), 234 (QD-613, key path prefixes), 235 (QD-640, format 1 reading past index_epoch) and 236-244 (QD-598 to QD-606: imports as bytes, history blobs, a push's sources, changeless parts, conflict branches, one EvsImport per push, an import's helper refs, overlay directories, tag refs); then the owner items accepted in bulk on 2026-11-06, 245-250 (QD-042, QD-047, QD-053, QD-233, QD-237, QD-276: the tainted bit from M3, retention without the reclaim, compaction Later, the 2 GiB cap, SHA-1 repos, working-tree sync and derived shares Later). Defect fixes and fills that bind the same rows went in as text: QD-091, QD-097, QD-152, QD-186, QD-268, QD-296, QD-450, QD-484 and QD-485, QD-485's Id.String() spelling of `ur/<sidecar_id>/…` governing QD-450's 32 hex digits for record streams' names, as the code builds them. The parts they name elsewhere went with them: §2's dropped-history bullet and risk row, §2.8's evs-2, evs-4 and evs-12, §16.8, §16.16, §16.17, §20.6, §20.7, FS-72, FS-94, §22.9's git row and §23.4.

`build.sh` on this folder reproduced DESIGN.md (SHA-256 `0d9cfd8cfdf81ccdcb60aad27c7c9d1260e14a7648b8d3f2900594c9b15a480a`) at the second piece, and the validation shows:

- **Ids.** None duplicated, undefined, or outside its own section; no new D-, Q- or FS- item.
- **Owner decisions.** All 250 rows are present and cited.
- **Superseded options.** 294 grep hits, each with a reading; the three on changed lines of the first piece (the pools family, at §11.13's needs row, §19.6's rewrapped settle row and §22.9's file-cluster list) were read on 2026-11-10, and the second piece's changed lines raised none. None is live.
- **Text.** No bare placeholders or HTML tags; the one research-sheet id stands. `v7/words.json` and `v7/text_checks.json` were regenerated.
- **The metadata list** is v11, whose header names what it adds (evs-2's erasure ref id, evs-4's keyless expired segments and retained deposits, evs-4's and evs-12's content kept until a later compaction), copied to `metadata_list.yml` by `make metadata`. evs-2 keeps the words "each ref's kind (shared, owned, deposit)", which testdata/evs/metadata_rows.yml quotes for EvsHeadSummary.ref_kind, and names the erasure ref in its own clause.
