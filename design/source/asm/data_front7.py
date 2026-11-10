# Front matter and the "Owner decisions" section for DESIGN.md, seventh assembly (2026-11-05), written from the
# section files as last edited (2026-11-05 00:02: the peer-review fix round, then the re-verification fix round),
# owner/DECISIONS.md (145 entries: 1-111 of 2026-11-03; 112-145 of 2026-11-04; entry 140's record corrected on
# 2026-11-04, which decides Q-EVS-9), owner/APPLY.md (§1-§9) and peer/orders/FRONT.md (FRONT-1 to FRONT-16, adapted
# where owner decisions 136-145 and the corrected record, all later than the orders, govern).
# Layered over data_front6.py as data_front6.py layers over data_front4.py: only what the current sections or the
# corrected record change is restated; everything else is data_front6.py's.
# Ids re-derived from v7/extract.json and v7/qfields.json (extract.py and fields.py on the current sections):
# 356 D- items (16 withdrawn, 1 decided); 175 Q- items, 148 decided by the owner (32 by 2026-11-04 entries),
# 11 closed by peer review 2026-11-04, 12 closed by the 2026-11-03 design-review round, 4 withdrawn, none open.
# Since the sixth assembly, Q-EVS-9 went from open (owner) to decided (owner decision 140, record corrected); no other
# Q- item changed status, and no X-owning or peer-closed item's text changed.
# Loaded with runpy. "@@OD:N@@" marks a link to row N of the decisions-by-number table; the assembler resolves it.
# "@@NAME@@" placeholders are counts that the assembler computes from the section text.
import json, pathlib, re, runpy

_HERE = pathlib.Path(__file__).parent
_P6 = runpy.run_path(str(_HERE / 'data_front6.py'))


def _swap(text, old, new):
    assert text.count(old) == 1, ('data_front7: expected one occurrence', old[:80])
    return text.replace(old, new)


TITLE = _P6['TITLE']

# The task's status line, verbatim.
STATUS = ("Status: draft for peer review, revised 2026-11-04 after the first peer review (see "
          "[DESIGN-REVIEW-RESPONSE.md](DESIGN-REVIEW-RESPONSE.md)). Nothing described here is implemented.")

SCOPE = _P6['SCOPE']
DIRECTIVE = _P6['DIRECTIVE']  # FRONT-1's listener exception still matches §2.8's statement (D-SMTP-23) and I-2.
RULES = _P6['RULES']

# Owner decisions 117 and 118, from §4.8, §23.4 and §23.9 as they now read: unchanged but for the exit-review bullet,
# which now carries §4.8's additive, release-compatible migrations and §23.9's "never change after" and FS-54.
BRANCH = _swap(_P6['BRANCH'], "once the pinned set passes its checks. Deploys",
               "once the pinned set passes its checks and its migrations are additive and release-compatible. Deploys")
BRANCH = _swap(BRANCH,
               "until its own milestone's Gn-out registers it (D-OPS-6), so one track's merge never applies the other's "
               "group and M3's pilot runs on production. Nothing waits",
               "until its own milestone's Gn-out registers it, and never changes after (D-OPS-6), so one track's merge "
               "never applies the other's group (FS-54) and M3's pilot runs on production (@@OD:118@@). Nothing waits")

# How to review: no owner question is open now (owner decision 140's corrected record decided Q-EVS-9), so the
# open-owner count and the "open for the owner" count drop out; the id families are unchanged (FI-1 to FI-14,
# FS-1 to FS-63, I-EVS-1 to I-EVS-7 and the rest, checked against the current sections).
HOW = _swap(_P6['HOW'],
            "the [open owner questions](#open-owner-questions) (@@NQOWNWORD@@, raised while the sections were edited to "
            "the 2026-11-04 peer review)",
            "the [open owner questions](#open-owner-questions) (none remain)")
HOW = _swap(HOW,
            "@@NQPEERC@@ closed by peer review on 2026-11-04, @@NQOPEN@@ open for the owner, @@NQCLOSED@@ closed by the "
            "2026-11-03 design-review round, which reviewers may reopen (§3.11), and @@NQW@@ withdrawn.",
            "@@NQPEERC@@ closed by peer review on 2026-11-04, @@NQCLOSED@@ closed by the 2026-11-03 design-review round, "
            "which reviewers may reopen (§3.11), and @@NQW@@ withdrawn; none is open.")
HOW = _swap(HOW, "peer review raised, all of 2026-11-04. Every such citation",
            "peer review raised, all of 2026-11-04; entry 140's record was corrected the same day, withdrawing its first "
            "~10-15 KiB of drive writes a push, a design-team estimate, for the binding budget (Q-EVS-9). Every such "
            "citation")

# FRONT-5 and FRONT-6, adapted: owner decisions 141-145 answered the peer review's owner questions after FRONT.md was
# written, and the corrected record of owner decision 140 decided Q-EVS-9, so no owner question is open. The second
# exception is new: §11.13, §19.9 and Q-OPS-10 state that owner decision 145's recorded sizing assumed batches shared
# across the whole load, which its own per-cluster placement rules out.
DECISIONS_INTRO = (
"The owner answered 111 questions on 2026-11-03, after the end-to-end-encryption directive, then on 2026-11-04 "
"14 more (entries 112-125) and 10 more (126-135), which settled every owner question that the fix rounds and the "
"conformance pass raised; 5 entries on the storage tier (136-140); and 5 more (141-145), which answered the five "
"owner questions that the 2026-11-04 peer review raised. That review closed the eleven Q- items left to it. The owner "
"then corrected entry 140's record: its ~10-15 KiB of drive writes a push was a design-team estimate, unreachable "
"when owner decision 2's head overwrite alone writes ~14 KiB, and the requirement is the PM9A3 profile itself, which "
"the design meets at ~27-43 KiB a push, gated at 43 KiB (D-TEST-11). That decided Q-EVS-9, the one owner question "
"raised while the sections were edited to the review, so no owner question is open. The sections are edited to these "
"answers. Where two answers disagree, owner/APPLY.md §2's supersession table and the later entries govern, and the "
"table of [owner decisions by number](#owner-decisions-by-number) notes each case. The assembly's checks (decision "
"citations, item status, residuals, and a grep for superseded options and for decided questions that still read as "
"open) found no section text that contradicts a decision, except where a decision's own clauses conflict: owner "
"decision 114's read-at-once and reap revocation do for Delegation-admitted agents, which §10.5 states as a residual; "
"and owner decision 145's sizing, ~490-650 pushes/s a set and four to five sets in year two, assumed batches shared "
"across the whole load, which its per-cluster placement rules out, so §11.13 and Q-OPS-10 size a set at ~400-450 "
"pushes/s and year two at five to six sets. This section lists the cross-cutting decisions, the open owner questions, "
"what peer review closed, and every decision with the sections that implement it."
)

X_INTRO = (
"X1-X20 are the cross-cutting decisions the research surfaced (CONVENTIONS §7). Each row is built from its owning "
"section's `[Xn]` Q- item: its question, the decision with the owner decisions that settle it, and its residual "
"as the item states it. Every X item is decided, and no residual waits for the owner; X6's row notes the one launch "
"call the owner keeps outside the Q- items."
)

# X | question | decision | owning § | Q id | residual. Every owning item's text (Q-TLS-1 to -4, Q-EVS-1, Q-ACL-1,
# Q-DNS-1 to -3, Q-MAIL-1 to -3 and -9, Q-SMTP-1, -4 and -5, Q-PROTO-1, Q-REPO-2, Q-CORE-1 and -2, Q-QUOTA-1, -2, -4
# to -6, Q-PROTO-3, Q-KEYS-1 to -4, -9 and -12, Q-OPS-1, Q-SDK-1, Q-PHASE-1, Q-BRIDGE-1, Q-EVS-2, Q-MCP-1) equals the
# sixth assembly's, so the rows stand; X13's residual drops Q-EVS-9 as open.
X_ROWS = []
for _r in _P6['X_ROWS']:
    if _r[0] == 'X13':
        assert _r[5].startswith('None in the item; Q-EVS-9 (open, owner)'), _r[5]
        _r = _r[:5] + ("None; Q-EVS-9, on the per-push figure in @@OD:140@@'s record, is decided by the record's "
                       "correction: the binding budget, gated at 43 KiB a push per drive (D-TEST-11).",)
    X_ROWS.append(_r)
assert [r[0] for r in X_ROWS] == [f"X{i}" for i in range(1, 21)]

OPEN_INTRO = (
"None. Every Q- item whose decider was the owner is decided. Owner decisions 112-135 answered those the fix rounds "
"and the conformance pass raised, and owner decisions 141-145 the five that the 2026-11-04 peer review raised "
"(Q-EVS-8, Q-MCP-6, Q-OPS-9, Q-KEYS-15, Q-OPS-10). Q-EVS-9, raised while the sections were edited to that review, is "
"decided by owner decision 140's record as corrected on 2026-11-04: the binding budget, gated at 43 KiB a push per "
"drive (D-TEST-11); the record's first ~10-15 KiB a push, a design-team estimate, is withdrawn. Outside the Q- items, "
"the owner keeps one launch call on measured data: accepting the SNI loss that M7's census measures, before BS1 "
"(D-MAIL-9; @@OD:34@@; §23.6)."
)
OPEN_OWNER = []

# FRONT-8 and FRONT-9, as in the sixth assembly; the residual list adds Q-OPS-3's, which the sections give to peer
# review (§19.14) and §23.6 places at M0's entry review. FRONT-8 predates that residual.
PEER_INTRO = (
"No Q- item is open for peer review. The items whose decider was peer review were closed on 2026-11-04; each now "
"reads “Closed by peer review 2026-11-04” in its section, with its answer, and §23.6 lists what each still gates. "
"Decided items leave two engineering residuals: Q-SDK-1's size spike, which decides C17 (Q-REPO-2), and Q-OPS-3's, "
"which leaves the Postgres-held sidecar rows to peer review: D-OPS-18's daily off-site dump, whose design closure "
"M0's entry review needs (§23.6), and 19.10's reconcile. The items the 2026-11-03 design-review round closed "
"([Appendix B](#appendix-b-open-questions-register)) were not closed by human peer review, and reviewers may reopen "
"them (§3.11)."
)
# Q id | question | closed by peer review 2026-11-04 | needed by. The eleven items' texts and §23.6's milestones
# (M0 Q-TEST-1, -2; M1 Q-CORE-4, Q-TEST-6; M2 Q-CTX-4, Q-KEYS-11, Q-EVS-6, Q-OPS-2; M4 Q-BRIDGE-2, Q-SDK-5; M5 Q-OPS-5)
# are unchanged since the sixth assembly.
PEER = list(_P6['PEER'])

INDEX_INTRO = (
"Every entry of the owner's record (owner/DECISIONS.md), by number: 1-111 from the interview of 2026-11-03; 112-125 "
"from the follow-up of 2026-11-04, 126-135 from its second round, 136-140 on the storage tier and 141-145 answering "
"the peer review's owner questions, all of 2026-11-04; row 140 follows the record as corrected on 2026-11-04. "
"\"Settles\" names the X and Q- items the entry decides, as the sections cite it. The decision is one line, faithful "
"to the record; where owner/APPLY.md §2 or a later entry supersedes, amends or confirms an entry, the line says so. "
"\"Implemented in\" lists the sections whose text cites the entry as \"owner decision N\"; a summary range such as "
"`owner decisions 1-145` does not count as citing each entry."
)

# Settles: each Q- item a section marks "Decided by owner ... (owner decision N ...)" now appears in row N (secondary
# items in parentheses, "moot" for the implied-moot ones, as rows 3, 45, 80 and 99 already did). Checked by
# v7/settles7.py; rows the sixth assembly already got right are untouched.
_SETTLES = {
    2: "X2; Q-EVS-1 (Q-OPS-3 moot)",
    4: "X10; Q-CORE-1, Q-CORE-2, Q-QUOTA-4 (Q-PROTO-2)",
    5: "X3 mechanism (Q-ACL-1, Q-KEYS-5)",
    6: "config repo read scope (Q-ACL-1)",
    7: "evs grants (Q-ACL-1)",
    8: "evs grant authority (Q-ACL-1)",
    11: "Q-QUOTA-5; Q-PROTO-3 (Q-TLS-5)",
    18: "X13; Q-OPS-1 (Q-OPS-3 moot)",
    20: "file cluster (Q-OPS-1)",
    21: "file cluster (Q-OPS-1)",
    22: "X9; Q-REPO-2 (Q-PHASE-3)",
    32: "Q-MAIL-3, Q-MAIL-10 (Q-PHASE-6 moot)",
    49: "Q-MCP-4 (Q-PHASE-3)",
    71: "dns hosting (Q-DNS-4)",
    75: "Q-MCP-3 (Q-ACL-7)",
    94: "storage topology (Q-OPS-1, Q-OPS-7)",
    99: "Q-TEST-3, Q-SMTP-1 (Q-PHASE-5 moot)",
    102: "Q-PHASE-4 (Q-PHASE-5 moot)",
    108: "Q-TRUST-6 (X17; Q-DNS-3)",
    110: "Q-TEAM-6 (Q-ACL-1, Q-KEYS-5)",
    118: "Q-OPS-8; Q-PHASE-8 (Q-REPO-4)",
    140: "Q-OPS-1 (X13): the write budget; Q-EVS-9 (record corrected)",
    145: "Q-OPS-10 (Q-OPS-1, X13)",
}
_DEC = {
    140: ("The design must fit the 8 × PM9A3 set as a hard budget, endurance binding: at most 0.8 DWPD and 50% of "
          "rated IOPS at the design load, reads preferred to writes, fewer drive bytes a push, and a global NVMe write "
          "budget from drive telemetry enforced by §11.13's shedder, which §22.8's M2 benchmark gates format 1 on. "
          "Corrected 2026-11-04: the record's first \"about 10-15 KiB\" a push was a design-team estimate, unreachable "
          "under @@OD:2@@'s ~14 KiB head overwrite; the design meets the budget at ~27-43 KiB, gated at 43 KiB "
          "(D-TEST-11), which decides Q-EVS-9."),
    145: ("The metadata tier grows only by adding metadata clusters, never MinIO pools: each new repo and its gkm group "
          "are placed at creation by a create-only `place/<repo_id>` on the first cluster, and all their objects stay "
          "there; a move tool is later. Supersedes @@OD:136@@'s second pool; the triggers stay. Its sizing (~490-650 "
          "pushes/s a set, four to five sets in year two) assumed batches shared across the whole load, which "
          "per-cluster placement rules out, so §11.13 and §19.9 size ~400-450 a set and five to six sets."),
}
_old = {n: (s, d) for (n, s, d) in _P6['INDEX']}
assert _old[140][1].endswith("Q-EVS-9 (open) asks whether the 10-15 KiB target binds, given @@OD:2@@'s head overwrite.")
assert _old[145][1].endswith("Supersedes @@OD:136@@'s second pool; the triggers stay.")
INDEX = [(n, _SETTLES.get(n, s), _DEC.get(n, d)) for (n, s, d) in _P6['INDEX']]
assert [r[0] for r in INDEX] == list(range(1, 146))
DATES = {n: ('2026-11-03' if n <= 111 else '2026-11-04') for n in range(1, 146)}

# Known gaps: section text that still contradicts an owner decision (where, text, decision, note). Filled from
# validation; empty when none is found.
KNOWN_GAPS_INTRO = _P6['KNOWN_GAPS_INTRO']
KNOWN_GAPS = []


# ------------------------------------------------------------------ guard against stale prose
# The prose above states that no Q- item is open, which Q- items peer review closed, and that Q-EVS-9 is decided by
# owner decision 140. When v7/extract.json is present (extract.py on the current sections), fail loudly if any of that
# no longer holds, with the assembler's status rule (assemble6.py's q_status).
def _check(ex_path=_HERE / 'v7' / 'extract.json'):
    if not ex_path.exists():
        return 'skipped: no v7/extract.json'
    peerc = '**Closed by peer review 2026-11-04:**'
    items = {it['id']: it for d in json.loads(ex_path.read_text()) for it in d['items']}

    def status(it):
        lab, t = it['label'], it['text']
        if 'withdrawn' in lab:
            return 'withdrawn'
        if 'closed' in lab:
            return 'closed'
        d, c = t.find('Decided by owner'), t.find(peerc)
        if d >= 0 and (c < 0 or d < c):
            return 'decided'
        return 'peer-closed' if c >= 0 else 'open'
    st = {i: status(it) for i, it in items.items() if i.startswith('Q-')}
    # From owner decision 197 (2026-11-09) owner questions are open again, which data_front10.py's OPEN_OWNER lists
    # and assemble10.py checks against the sections; only a question no later layer lists fails here.
    still_open = sorted(i for i, s in st.items() if s == 'open')
    # Owner decision 213 (accepted 2026-11-06, recorded 2026-11-10) asked for Q-REPO-6, on Linux updates.
    assert set(still_open) <= {'Q-BRIDGE-8', 'Q-SDK-7', 'Q-REPO-6'}, f"data_front7.py lists no such open Q- item: {still_open}"
    assert sorted(i for i, s in st.items() if s == 'peer-closed') == sorted(r[0] for r in PEER), 'PEER differs'
    assert '(owner decision 140, record corrected)' in items['Q-EVS-9']['text'], 'Q-EVS-9 no longer cites 140'
    for x, *_r in X_ROWS:
        assert any(re.search(rf'\[{x}\]', it['text']) for i, it in items.items() if i.startswith('Q-')), x
    return 'ok'


CHECK = _check()

# ---------------------------------------------------------------- close-out, 2026-11-05
# Entry 145's record was corrected to the sections' sizing; the id families grew (FI-15, I-EVS-8); X6's decision
# names the one platform listener that terminates TLS (T4-11).
_145_OLD = ("and owner decision 145's sizing, ~490-650 pushes/s a set and four to five sets in year two, assumed batches "
            "shared across the whole load, which its per-cluster placement rules out, so §11.13 and Q-OPS-10 size a set "
            "at ~400-450 pushes/s and year two at five to six sets.")
_145_NEW = ("which §10.5 states as a residual. Entry 145's record was corrected on 2026-11-05 to the sections' sizing: "
            "~490-650 pushes/s on the first set alone, ~400-450 a set once load spans clusters (batches per cluster), "
            "and five to six sets in year two.")
assert _145_OLD in DECISIONS_INTRO, 'decisions intro anchor'
DECISIONS_INTRO = DECISIONS_INTRO.replace("which §10.5 states as a residual;\n" if "which §10.5 states as a residual;\n" in DECISIONS_INTRO else "which §10.5 states as a residual; ", "")
DECISIONS_INTRO = DECISIONS_INTRO.replace(_145_OLD, _145_NEW)
assert 'four to five sets' not in DECISIONS_INTRO
_I145 = ("Its sizing (~490-650 pushes/s a set, four to five sets in year two) assumed batches shared across the whole "
         "load, which per-cluster placement rules out, so §11.13 and §19.9 size ~400-450 a set and five to six sets.")
INDEX = [(n, s, (d.replace(_I145, "Sizing, record corrected 2026-11-05 to the sections: ~490-650 pushes/s on the first "
                  "set alone, ~400-450 a set once load spans clusters, five to six sets in year two.") if n == 145 else d))
         for (n, s, d) in INDEX]
assert 'four to five sets' not in [d for (n, s, d) in INDEX if n == 145][0]
HOW = HOW.replace('FI-1 to FI-14', 'FI-1 to FI-15').replace('I-EVS-1 to I-EVS-7', 'I-EVS-1 to I-EVS-8')
assert 'FI-1 to FI-15' in HOW and 'I-EVS-1 to I-EVS-8' in HOW
X_ROWS = [(r[:2] + (r[2] + " The one exception is D-MAIL-10's platform listener for URnetwork's own report and role "
                    "addresses, which terminates TLS, parses headers and aggregate report data only and seals the raw "
                    "bytes (D-TRUST-4, §2.8 mx-4).",) + r[3:]) if r[0] == 'X6' else r for r in X_ROWS]
