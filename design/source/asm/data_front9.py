"""Front matter for the v1 additions (2026-11-05): layered over data_front8.py. Adds owner decisions 150-184:
the indexer, the search index, versionless objects, CLI/MCP search, the team directory, and the answers to the
owner questions the v1 briefs raised."""
import runpy, pathlib
_P8 = runpy.run_path(str(pathlib.Path(__file__).parent / 'data_front8.py'))
globals().update({k: v for k, v in _P8.items() if not k.startswith('__')})

INDEX = list(_P8['INDEX']) + [
    (150, "Terminology",
     "\"Indexer\" names a network's always-on point device for background services: receiving mail, mirroring "
     "record-class repos, search roll-ups and keeping the all partition synced. Always-on stays a device property."),
    (151, "v1 search index",
     "Each repo may keep an encrypted search index that its committers update with their commits, downloaded whole "
     "and searched locally: document-level trigram postings, with email and notes first."),
    (152, "v1 search index",
     "Latest is two time buckets of the per-repo window (30 days by default, 7-365) plus all; searches merge both "
     "buckets at once and all in the background or on \"search more\"; the newest version wins."),
    (153, "v1 search index",
     "Commits add their delta to the current bucket only; when a bucket expires, the roll-up merges its whole block "
     "into all once and drops it."),
    (154, "v1 search index",
     "Desktops, the daemon and indexers keep all synced; phones and browser tabs fetch it on \"search more\" or on "
     "Wi-Fi while charging; each device can override."),
    (155, "v1 search index",
     "On phones, all's hits show as ranked possible matches from the index's display fields, confirmed when opened; "
     "no body is fetched to verify them and no word index is added; desktops verify against local text."),
    (156, "v1 search index",
     "The index is on in every repo by default, and any repo admin can turn it off; per-commit cost stays bounded, "
     "with binaries skipped and only text indexed."),
    (157, "v1 search index",
     "The indexer runs roll-ups, else the first writer after a bucket expires, under a per-ref lock; both buckets "
     "stay searched until the roll-up lands."),
    (158, "VQ-1",
     "Versioning is set per object, and history follows it per version, as Perforce does: versions written while "
     "versioning was on stay, and only the head is kept while it is off."),
    (159, "VQ-2", "The search index is always versionless, so erasing index postings is real."),
    (160, "VQ-3",
     "Versionless files are allowed in every repo kind but config and mailcfg, and a repo admin can lock a repo to "
     "stay fully versioned."),
    (161, "VQ-4 (revised)",
     "Overwritten versionless content is purged as soon as it is safe, after about a minute for in-flight readers: "
     "the committing evs process deletes, a sweep catches failures, and there is no recovery window."),
    (162, "VQ-5",
     "Git refs stay fully versioned; git-lfs in v1 uses a versionless store that collects objects no ref tip and no "
     "commit of the last 30 days references."),
    (163, "VQ-6",
     "Versionless storage, the search index and its tools ship in v1 as storage format 2; format 1 reserves its "
     "numbers at M2, and older repos migrate."),
    (164, "VQ-7",
     "Each network has a default versioning rule, on the platform default off above 64 MiB, which admins edit in "
     "the config repo."),
    (165, "VQ-8, VQ-9",
     "Replaced content counts toward storage until it is purged; versionless always means head-only, with no "
     "keep-last-n."),
    (166, "v1 search",
     "`ur search` and MCP search tools search the repos the caller can read, including finding the agents working "
     "on a task."),
    (167, "Q-EVS-20",
     "A versioning rule applies when a path is created, from the repo's own rules, else the network's, else the "
     "platform's; existing paths keep their setting until a writer changes it."),
    (168, "Q-EVS-22",
     "A repo locked fully versioned keeps its search index: index files carry versioning value 2, which readers "
     "accept only under an index root."),
    (169, "Q-PHASE-9",
     "Format 2 is its own milestone, M10, on track A from M4's exit beside M6, with about three more engineers "
     "hired from M3's entry; RS2 does not wait for it."),
    (170, "Q-MCP-7",
     "In team networks, runs announce their title, project and branch by default, renewed hourly and handed off at "
     "the end, and members opt out; session contents stay in the vault, narrowing @@OD:126@@ to them."),
    (171, "Team directory",
     "One directory repo per team indexes every announcement of runs, repos and workers, each with who, what and "
     "where, and is where members request access to repos and workers."),
    (172, "Q-EVS-21",
     "Git-mode refs and record streams update `ur/index` at most once a minute per writer on 1 KiB blocks, else "
     "once every 5 minutes."),
    (173, "Q-EVS-19",
     "v1 ships a limited admin drop-history action on file-mode refs, refused in config and mailcfg repos; signed "
     "statements and hashes stay, and the dropped content goes."),
    (174, "Q-PHASE-10",
     "Format 2's drive-write gate is computed from M2's price table, then confirmed on production after its freeze "
     "within 10%, with no staging drives."),
    (175, "Q-SDK-6",
     "A phone's \"search more\" can go end to end to a designated indexer that reads the repo and return verified "
     "hits in padded replies; amended by @@OD:177@@ and @@OD:178@@."),
    (176, "Q-PROTO-4",
     "Connect rounds the byte reports of phone-to-indexer search contracts up to 128 KiB, hiding up to five search "
     "pages an hour."),
    (177, "Indexer default",
     "A network has no indexer by default: every service uses its fallback, and a phone downloads and searches its "
     "own index."),
    (178, "Remote search",
     "Phones use an indexer for \"search more\" once one is designated for the repo; a default network has none."),
    (179, "Q-MCP-8",
     "In v1, access to a worker means reaching the services it announces, under the access policy with an "
     "approver, an expiry and receipts."),
    (180, "Q-ACL-11",
     "The device's owner, or a tagged sidecar's sponsor, approves reach to another member's device, through "
     "`autogroup:dst-owner`, amending @@OD:74@@ for this case."),
    (181, "Q-MCP-9",
     "Every repo a team creates is announced in the directory by default; owners can create private repos and "
     "revoke an announcement, which erases the name."),
    (182, "Q-KEYS-16",
     "The directory is its own MLS group under the config group's leaves rule: member devices past the first 1,000 "
     "read it through wraps (@@OD:144@@)."),
    (183, "Q-EVS-23",
     "A drop waits out a 7-day window in which any repo admin can cancel it; `now` skips the wait."),
    (184, "Q-ABUSE-7",
     "A preservation hold defers a drop's deletions silently: the drop reads and bills as finished, and nothing "
     "reveals the hold (@@OD:93@@)."),
]
assert [r[0] for r in INDEX] == list(range(1, 185))
DATES = dict(_P8['DATES'])
DATES.update({n: '2026-11-05' for n in range(150, 185)})
_ANCHOR = "This section lists the cross-cutting decisions"
assert _ANCHOR in _P8['DECISIONS_INTRO']
DECISIONS_INTRO = _P8['DECISIONS_INTRO'].replace(
    _ANCHOR,
    "Also on 2026-11-05 the owner named the indexer (150), set the v1 search index, versionless objects and CLI and "
    "MCP search (151-166), created the team directory (171), set no indexer by default (177, 178), and answered "
    "every owner question the v1 designs raised (167-170, 172-176, 179-184), so no owner question is open. " + _ANCHOR)

# The business documents moved into design/ (2026-11-05): point the front matter's research-sheet link there.
for _k, _v in list(globals().items()):
    if not _k.startswith('_') and isinstance(_v, str) and '[design-research/](design-research/)' in _v:
        globals()[_k] = _v.replace('[design-research/](design-research/)', '[design/design-research/](design/design-research/)')

STATUS = ("Status: draft for peer review, revised 2026-11-04 after the first peer review (see "
          "[DESIGN-REVIEW-RESPONSE.md](DESIGN-REVIEW-RESPONSE.md)) and on 2026-11-05 with the v1 additions of owner "
          "decisions 150-184 (versionless objects, the search index, CLI and MCP search, the indexer, the team directory "
          "and history drops), which no peer review has checked yet. Nothing described here is implemented.")

# Id families as of the v1 build (2026-11-05).
_ID_FIX = [("`I-1`..`I-18`", "`I-1`..`I-20`"), ("C1-C18 (connect changes", "C1-C19 (connect changes"),
           ("F1-F10 (flows", "F1-F13 (flows"), ("S1-S10 (test scenarios", "S1-S13 (test scenarios"),
           ("FI-1 to FI-15 (", "FI-1 to FI-27 ("), ("FS-1 to FS-63 (", "FS-1 to FS-98 ("),
           ("I-EVS-1 to I-EVS-8 (", "I-EVS-1 to I-EVS-15 ("), ("M0-M9 (milestones", "M0-M10 (milestones")]
for _k, _v in list(globals().items()):
    if not _k.startswith('_') and isinstance(_v, str):
        for _a, _b in _ID_FIX:
            _v = _v.replace(_a, _b)
        globals()[_k] = _v
