# Design details

Detailed designs for the hard algorithmic problems that remained in DESIGN.md on 2026-11-09. Each problem's brief is in `.stack/design-problems.md`. The owner directed a fifth agent, on Fable at max effort, to work them out here, and directed that implementation in each problem's area wait until its section is complete.

Where a complete section and DESIGN.md differ, the section governs the tasks it names, until a design-records track folds it into `design/source/`. Each section ends with its proposed DESIGN.md text and its owner questions.

Status values: `pending`, `in progress`, `complete (date)`, or `complete pending owner question <file>` (built on the stated recommendation).

| # | Problem | Tasks held | Status |
|---|---|---|---|
| 1 | Search index merges, roll-ups and the journal (§11.14) | 7 | pending |
| 2 | Storage consistency under stalled writes: segment GC and the MinIO settle rules (§11.13, §19.6) | 4 | pending |
| 3 | Zero-knowledge proofs of TLS delivery for outbound mail (smtpproof; §14.5) | 5 | pending |
| 4 | Forwarding in the apps' VPN component: key, verification and size (owner decision 197) | 40 | pending |
| 5 | Authorization-log verdicts across folds (§7.9) | 13 | pending |
| 6 | MLS group key management (§10) | 13 | pending |
| 7 | Remote search across designated indexers (§11.14, §18.4) | 3 | pending |
| 8 | Git and evs in both directions | 3 | pending |
| 9 | Client path epochs and re-tokenizing | 3 | pending |
| 10 | DROP lists a phone can check (§11.6, §11.7, §11.9) | 5 | pending |
| 11 | Canonical text extraction and exact body sizes for search | 2 | pending |
| 12 | Bridge compiler and NAT engine (§17) | 4 | pending |
| 13 | Smaller scheduling problems: closure pacing, quota leases, socket registration | 4 | pending |

## 1. Search index merges, roll-ups and the journal (§11.14)

Status: pending

Tasks held until complete: SEARCH-M10-10, SEARCH-M10-11, SEARCH-M10-13, SEARCH-M10-14, SEARCH-M10-15, SEARCH-M10-35, TEST-M10-02.

## 2. Storage consistency under stalled writes: segment GC and the MinIO settle rules (§11.13, §19.6)

Status: pending

Tasks held until complete: EVSB-M10-01, EVSB-M10-02, EVSB-M2-12, EVSB-M2-17.

## 3. Zero-knowledge proofs of TLS delivery for outbound mail (smtpproof; §14.5)

Status: pending

Tasks held until complete: SMTP-M9-07, SMTP-M9-08, SMTP-M9-09, SMTP-M9-13, SMTP-M9-32.

## 4. Forwarding in the apps' VPN component: key, verification and size (owner decision 197)

Status: pending

Tasks held until complete: BRIDGE-M2-01, BRIDGE-M4-15, BRIDGE-M4-18, BRIDGE-M4-19, BRIDGE-M4-20, BRIDGE-M4-22, BRIDGE-M6-05, BRIDGE-M6-06, BRIDGE-M6-07, BRIDGE-M6-08, BRIDGE-M8-01, BRIDGE-M8-02, BRIDGE-M8-03, SDK-M10-01, SDK-M10-02, SDK-M10-03, SDK-M10-04, SDK-M10-05, SDK-M10-06, SDK-M3-01, SDK-M4-04, SDK-M4-05, SDK-M4-06, SDK-M4-08, SDK-M4-09, SDK-M6-02, SDK-M6-03, SDK-M8-01, SDK-M8-02, SDK-M8-03, SDK-M8-04, SDK-M8-05, SDK-M8-06, SDK-M8-07, SDK-M8-08, SDK-M8-10, SDK-M8-12, SDK-M8-14, SDK-M8-15, SDK-M9-01.

## 5. Authorization-log verdicts across folds (§7.9)

Status: pending

Tasks held until complete: CORE-M3-02, CORE-M3-03, TEAM-M10-01, TEAM-M2-04, TEAM-M2-05, TEAM-M2-06, TEAM-M2-07, TEAM-M2-09, TEAM-M2-10, TEAM-M2-17, TEAM-M2-18, TEAM-M2-19, TEAM-M3-02.

## 6. MLS group key management (§10)

Status: pending

Tasks held until complete: KEYS-M2-19, KEYS-M2-20, KEYS-M2-21, KEYS-M2-22, KEYS-M2-23, KEYS-M2-24, KEYS-M2-25, KEYS-M2-26, KEYS-M2-27, KEYS-M2-28, KEYS-M2-29, KEYS-M2-31, KEYS-M4-01.

## 7. Remote search across designated indexers (§11.14, §18.4)

Status: pending

Tasks held until complete: SEARCH-M10-19, SEARCH-M10-32, SEARCH-M10-33.

## 8. Git and evs in both directions

Status: pending

Tasks held until complete: EVS1-M2-34, EVS1-M2-35, EVS1-M2-36.

## 9. Client path epochs and re-tokenizing

Status: pending

Tasks held until complete: EVS1-M2-28, EVS1-M2-29, EVS1-M2-30.

## 10. DROP lists a phone can check (§11.6, §11.7, §11.9)

Status: pending

Tasks held until complete: EVS2-M10-09, EVS2-M10-10, EVS2-M10-22, EVSB-M10-03, EVSB-M10-04.

## 11. Canonical text extraction and exact body sizes for search

Status: pending

Tasks held until complete: SEARCH-M10-31, SEARCH-M10-36.

## 12. Bridge compiler and NAT engine (§17)

Status: pending

Tasks held until complete: BRIDGE-M4-16, BRIDGE-M4-17, BRIDGE-M6-03, BRIDGE-M6-04.

## 13. Smaller scheduling problems: closure pacing, quota leases, socket registration

Status: pending

Tasks held until complete: QUOTA-M2-07, SOCK-M5-05, SOCK-M5-06, SOCK-M5-07.
