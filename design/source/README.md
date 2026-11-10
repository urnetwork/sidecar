# DESIGN.md sources

[DESIGN.md](../../DESIGN.md) is generated. This folder holds what it is built from: the 23 section files, the owner's decision record, the conventions the design was written under, and the scripts that assemble and validate it. They came from the design sessions' working folder on 2026-11-06. From then on this folder is the source of truth. Edit here and rebuild; never edit DESIGN.md by hand, since the next build overwrites it.

## Contents

| Path | What it is |
|---|---|
| `sections/01-CTX.md` … `sections/23-PHASE.md` | DESIGN.md §1-§23, one file per section. The build copies them verbatim, adding only links. |
| `owner/DECISIONS.md` | The owner's record, entries 1-214. Each entry gives the question, the answer, what it costs and the options not taken. "Owner decision N" in DESIGN.md cites entry N. The file ends with owner instructions that carry no number. |
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

## Adding owner decision N (215 onward)

1. Add entry N to `owner/DECISIONS.md`: the question, the answer, its cost, the options not taken, and what raised it.
2. In `asm/data_front10.py`, append `(N, "<what it settles>", "<one line>")` to `INDEX`, add `DATES[N]`, and raise the `assert` to `list(range(1, N + 1))`. Update `STATUS` and `DECISIONS_INTRO` where they name a range. `@@OD:k@@` writes a link to decision k.
3. Set `MAXD = N` in `asm/assemble10.py` and `asm/cites10.py`.
4. In `asm/validate10.py`, raise both `list(range(1, N))` checks, `owner_record` and `decision_rows`, to `N + 1`, and add N's date to `LATE_DATES`, which `dates_ok` reads from 198 on, since the build's answers are numbered as they are folded and a later number can carry an earlier day (2026-11-06's bulk acceptance). A day no earlier entry has also needs `decision_rows`' date pattern, as 2026-11-10 was added for decision 198.
5. In the sections, mark the question "**Decided by owner YYYY-MM-DD (owner decision N):**", or "**Amended by owner …**" for a change to an earlier answer. Cite "owner decision N" in every section that implements it: the validator fails any decision that no section cites. That is D-ARCH-4's assembly check, which G0 requires (§23.8).
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

The design-records track for §2 and §3 folded those sections' items from sidecar/DESIGN-AMENDMENTS.md. The owner's answers that change a behavior or a rule became owner decisions 198-214, each citing its ledger id: those decided one at a time on 2026-11-10 (198-206), and the owner-class items the owner accepted in bulk on 2026-11-06 (207-214), numbered as they were folded. Accepted defect fixes, readings and fills went in as text. Decision 213 asked for Q-REPO-6, a third open owner question, which the front matter's table lists, §23.6 places and `data_front7.py`'s check now allows. `build.sh` on this folder reproduced DESIGN.md (SHA-256 `b9c6bb9a7f76f724b37a91c186b4c066928b2aa694595ea635a3af7961f5a7bb`) at that track's last fold, and the validation shows:

- **Ids.** None duplicated, undefined, or outside its own section; one new Q- item, Q-REPO-6, with its register summary.
- **Owner decisions.** All 214 rows are present and cited; row 183 notes decision 204's amendment of its 25-minute fence. `validate10.py`'s `LATE_DATES` gives each row from 198 its date.
- **Superseded options.** 303 grep hits, each with a reading; those on changed lines were read on 2026-11-10. None is live.
- **Text.** No bare placeholders or HTML tags; the one research-sheet id stands.
- **The metadata list** is v10, whose header names what it adds, copied to `metadata_list.yml` by `make metadata`. Two new rows the owner asked for, ext rows for Cloudflare at https://ur.io and for the abuse mailboxes' provider, wait on question `dr-s2-s3-new-metadata-rows.md`, since §22.7's guard needs each new row's `planned` line in `testdata/metadata/fields.yml` in the same commit; QD-206's row for the file clusters' bookkeeping went into evs-10, the file cluster's own row.
