# DESIGN.md peer review: the design team's response

## 1. Reviews answered

- **Date:** 2026-11-04; final state 2026-11-05. **From:** the design team. **For:** the reviewers and the owner.
- **Reviews of the 2026-11-03 draft** (DESIGN.md, SHA-256 `12aba8d5…`, 9,256 lines):
  - R1, DESIGN-REVIEW1.md (Astra);
  - R2, DESIGN-REVIEW2.md (Sol);
  - R3, DESIGN-REVIEW3.md.
- **Reviews of the 2026-11-04 draft** (DESIGN.md, SHA-256 `1f33a2fa…`, 9,754 lines):
  - R1b, DESIGN-REVIEW1b.md (Astra);
  - R3b, DESIGN-REVIEW3b.md.
- **Also folded in:** the internal reports CHECK4 and CRITIC4. Their points overlap the reviews', and the same entries dispose of them. They are listed under "Sources" where they apply. peer/INDEX.md indexes them; section 4 of this file does not.
- **Second round:** a final panel of eight clusters re-checked the five reviews' findings against the section files after FIX3 (peer/FINAL-*.md, 2026-11-05; section 6.4).
- **Final rounds:** rounds 3 and 4 fixed what the panel left, independent checkers re-checked its ten majors, and six checkers cross-checked the sections (2026-11-05; section 6.7). Rounds 5 and 6 then applied owner decisions 146-149 to the four majors the final re-check left partial (2026-11-05; section 6.8). The statuses here are final.
- **Revised DESIGN.md** (SHA-256 `8bff53d4cbb23d116753cd8ada85fd58e53ddeaf0e120a8d592aa83aebd251aa`, 14,724 lines, 254,532 words, the file now in the sidecar checkout): the current build, assembled from the 23 section files as round 6 left them (sections/01-CTX.md to 23-PHASE.md, last edited 2026-11-05 09:51), under owner decisions 1-149. Its validation passed: no duplicate or undefined ids, every link resolving, no live superseded option, no open question, and all 149 owner decisions cited. All §N.k references and ids below are to that text.

**How to read this.** Section 3 has one entry per consolidated finding, T1-01 to T5-35, grouped by theme. Section 4 maps every id from each review to its entry.

- **Sources** use the reviews' own ids: R1 F01, R3 C1, R3b finding 1, R1b invariant 1, and so on.
- **Verdicts:**
  - *valid*;
  - *partly valid*;
  - *accepted residual*: true, but a consequence of an owner decision, so it is disclosed rather than changed;
  - *already fixed*: fixed in the draft the reviewer read;
  - *invalid*.
- **Dispositions:**
  - *fix*;
  - *fix-modified*: fixed in a way other than the review proposed, with the reason given;
  - *disclose*;
  - *decline*;
  - *merged*: governed by another entry;
  - *owner item*: the owner has now decided it.
- **Tests** name deterministic schedules (FS-n in §22.8, checked against the FI-n invariants), §22.5's component rows, §22.6's fuzz targets and §22.7's suites. None of them has run: nothing in DESIGN.md is implemented.
- **Final status** (*Final* in section 3, the last column in sections 4 and 5) is the second-round panel's, as the final rounds changed it (sections 6.7 and 6.8):
  - *resolved*: the text does what the reviewer asked, or an equivalent, and the main failure trace is tested; for a gap the panel left, an independent re-check found it closed;
  - *fixed*: one of rounds 3 to 6 closed the gap the panel left and the build validated, but no independent reviewer has re-checked the fix;
  - *partial*: something the reviewer explicitly asked for is still missing (section 6.1);
  - *disclosed*: an owner decision keeps the residual, and the text states it truthfully;
  - *declined-as-stated*: we declined, and our reason holds;
  - *not re-checked*: outside the panel's clusters.

  The panel marked nothing *open*. "New" names the new issues it found (SC-N1 to ST-N6, section 6.2), with their final status.

## 2. Summary

### 2.1 What changed

**Storage commit protocol (§11).** A ref's state now changes only by its head's If-Match. Everything else a push writes is immutable, or a cache rebuilt from committed records. No answer deletes anything: a dead push's record and slots go only when evacuation's Resolve finds the push dead (§11.8; I-EVS-1 to I-EVS-7; D-EVS-13, D-EVS-23). Git-mode refs commit only on their tip, and file-mode refs keep disjoint landing (owner decision 141; D-EVS-22). The revocation gate is enforced at the head CAS (D-EVS-18). Path epochs, deletion and erasure became state machines with fences (D-EVS-12, D-EVS-19, D-EVS-26). Head readers verify signed statements from their pin (Q-EVS-6; D-EVS-24). Mirrors hold slots and re-seed under EvsReseed (D-EVS-17).

**Authority and keys (§6-§8, §10).** One hash-chained authorization log per network replaces bases plus delta sequence numbers. Every consumer pins (n, A_n), and the gate compares positional shrinks and timed expiries (§7.9, §10.6; D-TEAM-19). A `gen/<g>` claim is the only place a generation exists (D-KEYS-15). Delegations get DelegationWraps, and owner decision 114's reap residual is stated where readers will see it (D-KEYS-16). §2.8 publishes one 72-hour bound with its exceptions. Witnesses compare authorization pins, generations and ref heads from M2, and get control contracts at M4 (D-PROTO-17, D-PROTO-18). The rest of the theme adds a signed recovery veto (D-TEAM-21), typed `Signed` records (D-PROTO-7), drop keys inside GenRotate (D-KEYS-17) and one leaves rule for owner decision 144 (§7.9).

**Runtime and approvals (§4, §5, §16, §18).** Approval uses are reserved before their effect, and decisions bind their requester and auth pin (D-MCP-11, D-MCP-12). Harness evidence cannot be bound to the harness binary, so under owner decision 142 it counts in a tainted run only where a rule names it (D-MCP-9). Restore writes only a run's attributed edits (attribution still lacks a pre-edit hash: section 6.1), taint survives restarts, and MCP signs no policy (D-MCP-15 to D-MCP-17). The SDK separates transport loss from revocation and reports keystore states (D-SDK-14, D-SDK-15). Wakes stay within one Redis slot, and HTTPS-only clients hold a poll lease (D-SDK-16, D-SDK-17). Browser keys live in their own origin, the page Worker links no connect package, and the device role is `sidecar/device` (D-SDK-18 to D-SDK-20). Refresh needs a DPoP proof (Q-CORE-4).

**Edges, mail and network (§6, §9, §12-§15, §17).** The SMTP proof now covers the MX's authenticated replies (D-SMTP-22), and DATA mode's size cap is disclosed. CAA has strong and weak modes (D-DNS-9), and strict mail's claim is limited to customer-signed MX and TLSA (D-MAIL-12). Custom SNI reaches tlsedge (D-TLS-12), and dispatch keys on the signed application mode (D-TLS-13). Reports get a bounded aggregate parser (D-SMTP-23), and receivers seal reception-time evidence (D-MAIL-14). The REQUIRETLS label, the report-listener exception (still missing from D-MAIL-1 and the X6 row: section 6.1) and iOS foreground receipt are disclosed, and burner DKIM keeps the burner's MX (D-DNS-11). Sockets get a control-plane bound without count caps (D-SOCK-15). Native flows need a WindowDelegation under C13's seal, and the bridge gains verified states, an own-listener guard, a share preflight and a dial fence (D-PROTO-19, D-BRIDGE-17 to D-BRIDGE-21).

**Ops, tests and phasing (§19-§23).** The durability table now says what holds, but for two corrections (SL-N4, OT-N1): RPO 0 for drives and hosts, and at the site only what devices hold (§19.6). Sidecar tables get a daily off-site dump (D-OPS-18), and sets get protection states. §19.10 recovers from a Postgres or site loss with CT replay, re-registration and log resumption. Owner decision 143 pages infrastructure out of hours from M3. Billing uses pre-aggregated daily meters, idempotent usage batches, relayed reservations and one draw order (D-QUOTA-8, D-QUOTA-4, D-QUOTA-9), and holds have kinds (D-ABUSE-6). Deterministic fault schedules FS-1 to FS-63 run against FI-1 to FI-14, with a TLA+ model and Porcupine (D-TEST-10). Formats freeze twice (D-PHASE-7), 0x0010 needs an interop artifact, and unfinished migrations stay behind a build tag (D-OPS-6). G0's word ceilings gave way to a density rule (T5-30).

**The storage tier and the IOPS fit (owner decisions 136-140, 145).** The first metadata cluster is 8 × Samsung PM9A3 1.92 TB at EC:4 (R-OPS-12). Every drive takes every metadata write, so endurance binds before IOPS. The redesign uses ~9 KiB heads, group-committed batches, lazy index folds, hourly evacuation, upload receipts, Redis soft state with verified caches, tuned XFS and MinIO, and a write budget priced in drive bytes (D-EVS-29 to D-EVS-34, D-KEYS-21, D-OPS-19). By the model, an inference until §22.8 measures it, year one writes ~43 KiB a push per drive at 0.40 DWPD. One set carries ~400-450 pushes/s (~530-600 on 1 KiB blocks), and year two needs five to six clusters, added whole, never as MinIO pools (owner decision 145). D-TEST-11 gates format 1 on at most 43 KiB per push per drive. Q-EVS-9 is closed: owner decision 140's binding target is the drive budget, which the design meets at ~27-43 KiB a push. The record's first ~10-15 KiB estimate lay below the ~14 KiB the head overwrite alone writes (section 6.3).

**After the second round.** The final panel (section 6.4) found 224 of its 275 checks resolved and none open. It marks 24 findings partial (section 6.1). It found 61 new issues, 10 of them major (section 6.2):
- lazy folds and the file-mode path CAS (ST-N1);
- a false git non-fast-forward after a fence (SC-N1);
- erasure at the storage limit (SL-N1);
- the path-epoch copy of directories a fold moved (SL-N2);
- config for uncovered ephemeral sidecars (AU-N1);
- a one-hop compromise cascade (AU-N2);
- §2.8's chain of witnesses (WR-N1);
- the `secret` kind through MCP (RT-N1);
- two restore gaps (OT-N1, OT-N2).

### 2.2 Counts

155 consolidated entries cover the 264 items section 4 indexes (R1 42, R1b 54, R2 51, R3 80, R3b 37), and the internal reports' items.

| Theme | Entries | Valid | Partly valid | Accepted residual | Already fixed | Invalid |
|---|---:|---:|---:|---:|---:|---:|
| T1 storage commit protocol | 24 | 19 | 2 | 0 | 3 | 0 |
| T2 authority and keys | 41 | 34 | 4 | 3 | 0 | 0 |
| T3 runtime and approvals | 27 | 21 | 5 | 0 | 1 | 0 |
| T4 edges, mail and network | 28 | 19 | 3 | 3 | 3 | 0 |
| T5 ops, tests and phasing | 35 | 22 | 10 | 0 | 2 | 1 |
| **Total** | **155** | **115** | **24** | **6** | **9** | **1** |

| Theme | Fix | Fix-modified | Disclose | Decline | Merged | Owner item |
|---|---:|---:|---:|---:|---:|---:|
| T1 | 18 | 3 | 1 | 2 | 0 | 0 |
| T2 | 29 | 2 | 4 | 0 | 5 | 1 |
| T3 | 21 | 3 | 1 | 1 | 0 | 1 |
| T4 | 18 | 2 | 6 | 1 | 1 | 0 |
| T5 | 28 | 3 | 0 | 3 | 0 | 1 |
| **Total** | **114** | **13** | **12** | **7** | **6** | **3** |

- **Owner items.** There are four, all now decided:
  - T2-33 (Q-KEYS-15, owner decision 144);
  - T3-05 (Q-MCP-6, owner decision 142);
  - T5-07 (Q-OPS-9, owner decision 143);
  - T1-05, a fix whose git model the owner confirmed (Q-EVS-8, owner decision 141).
- **The storage tier.** The owner decided Q-OPS-10 (owner decision 145).
- **Peer-review questions.** Peer review closed the eleven questions left to it, plus Q-QUOTA-3's residual (section 5). The final panel found two closures partial, Q-CTX-4 and Q-OPS-2, and round 3 fixed both.
- **Raised during the response.** Q-EVS-9 is closed by owner decision 140's corrected record (section 6.3). No owner question is open.

**Final status.** An entry takes the weakest final status of a finding it answers, where the gap lies in that entry's mechanism; a gap in another entry's mechanism is noted as related. The final rounds moved 14 of the panel's 21 partial entries: 13 to *fixed*, and T5-04 to *resolved*, its two majors re-checked (section 6.7). Of the other seven, the close-out build resolved T4-11, and rounds 5 and 6 moved T1-01, T1-16, T2-05, T2-06, T2-18 and T5-12 to *fixed* (owner decisions 146-149; section 6.8). No entry is partial.

| Theme | Entries | Resolved | Fixed | Partial | Disclosed | Declined as stated | Not re-checked |
|---|---:|---:|---:|---:|---:|---:|---:|
| T1 | 24 | 17 | 5 | 0 | 2 | 0 | 0 |
| T2 | 41 | 25 | 7 | 0 | 4 | 0 | 5 |
| T3 | 27 | 22 | 2 | 0 | 2 | 1 | 0 |
| T4 | 28 | 22 | 1 | 0 | 4 | 0 | 1 |
| T5 | 35 | 24 | 4 | 0 | 0 | 1 | 6 |
| **Total** | **155** | **110** | **19** | **0** | **12** | **2** | **12** |

| Review | Items | Checked directly | Resolved | Fixed | Partial | Disclosed | Declined as stated | Not re-checked |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| R1 | 42 | 41 | 35 | 3 | 0 | 3 | 1 | 0 |
| R1b | 54 | 54 | 48 | 6 | 0 | 0 | 0 | 0 |
| R2 | 51 | 46 | 43 | 2 | 0 | 4 | 1 | 1 |
| R3 | 80 | 46 | 49 | 8 | 0 | 14 | 1 | 8 |
| R3b | 37 | 24 | 23 | 6 | 0 | 7 | 1 | 0 |
| **Total** | **264** | **211** | **198** | **25** | **0** | **28** | **4** | **9** |

- **Rows not checked directly** take the status of the same finding under another name, of their entries or of their question (section 4).
- **New issues.** The panel found 61, 10 of them major (section 6.2). Rounds 3 and 4 fixed 50 of the 51 minor ones, and the owner's record had already fixed the last (ST-N6). Of the majors, six re-checked resolved, and rounds 5 and 6 fixed the other four, SL-N1, WR-N1, ST-N1 and AU-N2, under owner decisions 146-149 (section 6.8).

### 2.3 What may freeze at M2, and the gates that remain

Nothing is frozen by this response. Under D-PHASE-7, each format freezes twice: its specification at its milestone's entry review (Gn-in) and its bytes at the exit review (Gn-out) (§22.10, §23.8). Before a final freeze, only local, T3, canary and staging environments hold the format. Production data starts at M3.

- **At M2's entry: the specifications of §7.9's records, format 1, credential 0xF552 and suite 0x0010's fields.**
  - The five reviews and the second-round panel are the peer review those specifications needed, and Q-EVS-8 is decided.
  - What remains:
    - the open items that sections 6.1 and 6.2 place at G0 or M2-in and the residuals of section 6.8, and a reviewer's re-check of the items fixed there, the majors ST-N1, SL-N1, AU-N2 and WR-N1 among them;
    - `EvsCommit.tla` written and passing TLC at its bounds;
    - the FS rows written as tests against the fakes;
    - the vector schemas fixed;
    - RECORD.md reviewed (owner decision 25).
- **At M2's exit: format 1's bytes and suite 0x0010.** This needs:
  - §23.6's M2 schedules (FS-1 to FS-12, FS-14 to FS-18, FS-19's config read, FS-20, FS-22 to FS-24, FS-40, FS-44, FS-45, FS-47, FS-53, FS-57 to FS-63) passing on their tiers;
  - Porcupine;
  - §22.10's 0x0010 interop artifact with tmc/mls;
  - mlswg vectors and X-Wing KATs;
  - fuzz seeds;
  - the twenty-agent test;
  - §10.6's sizes;
  - the storage benchmark with D-TEST-11's `nvme` gate, run on the production hosts' PM9A3 set, used as M2's staging cluster.
  - Format 1's erasure and deposit bytes freeze on §22.5's §11 cases, FS-23 and FS-47. FS-13, FS-23's mailbox case and FS-47's mail case keep their M7 gates (AU-N11, SL-N1).
- **`record.proto`: at M3.** Its specification freezes at M3's entry (RECORD.md's semantics and the hashed bytes named, with owner decision 142's tainted-run rule), and its bytes at M3's exit (vectors over stored bytes, fuzz, FS-25 to FS-29).
- **The storage benchmark:**
  - `nvme` at M2's exit;
  - again on production before M3's pilot;
  - the `hdd` row before the segment cluster holds data (M3).
- **Later gates:**
  - the escrow order at M6's entry (FS-46 and §20.9's benchmark, run on the comparator M4 builds dark, its index pending in MG6: OT-N3);
  - `smtpproof/SPEC.md` at M9.

### 2.4 Owner decisions taken during the response

- **136.** The initial storage tier is 4 hosts, each with 2 × 2 TB NVMe and 16 × 16 TB HDDs.
  - MinIO stays the system of record. Redis holds only rebuildable soft state and a verified read cache.
  - History packs after 24 h, and a small repo's packs at 256 KiB or 7 days.
  - XFS gets `-i maxpct=25`.
  - The next set is ordered at 50% raw space, 40% of inodes or a sustained 0.5 DWPD.
- **137.** NVMe drive model: Samsung PM963 1.92 TB. Superseded for the initial cluster by 138.
- **138.** The initial metadata drives are Samsung PM9A3 1.92 TB (MZ1L21T9HCLS): 8 in the set, 2 per host, EC:4.
- **139.** The initial deployment is PM9A3 only, with 2-4 PM9A3 spares. Every later set is homogeneous.
- **140.** The storage design must fit the 8 × PM9A3 set as a hard budget: at most 0.8 DWPD and 50% of rated IOPS per drive, reads preferred over writes, a global write budget measured from drive telemetry, and format 1 gated on bytes written per push. Its record first gave ~10-15 KiB of drive writes a push, a design-team estimate; the corrected record makes the binding budget the target, which closed Q-EVS-9 (section 6.3).
- **141.** Q-EVS-8 (a): git-mode refs commit only on their tip; file-mode refs keep disjoint landing.
- **142.** Q-MCP-6 (c): in a tainted run, harness evidence approves an outward action only where the matching `requests` rule names it, never through `evidenceDefault`.
- **143.** Q-OPS-9 (a): a two-person out-of-hours infrastructure rota on one pager service from M3, with 30-minute acknowledgment and escalation, for page classes only.
- **144.** Q-KEYS-15 (b): member devices past a network's first 1,000 read the config group by per-generation wraps from the start, with no member-device cap. The team had recommended (a), a cap of 1,000.
- **145.** Q-OPS-10 (b): the metadata tier grows only by adding metadata clusters, never MinIO pools. Repos are placed at creation by a create-only `place/<repo_id>` on the first cluster. Its record, corrected 2026-11-04 (ST-N6), keeps T6's single-stream ~490-650 pushes/s for the first set alone and gives ~400-450 a set once load spans clusters and five to six sets in year two, as §11.13 and Q-OPS-10 do.
- **146.** SL-N1 (2026-11-05): each erasing sidecar has its own daily closure allowance in pro.yml, which §21's abuse controls may tighten but never below a fixed floor.
- **147.** WR-N1 (2026-11-05): phones keep their newest 64 KiB of authorization-log entries and serve proofs; §7.9 stands, and FS-17 follows it.
- **148.** ST-N1 (2026-11-05): removal folds never blind-delete an index entry; they write a versioned tombstone marker by If-Match, garbage-collected once the fold horizon passes it.
- **149.** AU-N2 (2026-11-05): a scoped admission by a binding the compromise cascade restored activates through the 72 h recovery window with admin veto; the cascade re-seals keychains, and backups exposed to the voided binding are re-enrolled.
- **150.** Terminology (2026-11-05): a network's always-on point device for its background services is the "indexer"; the next pass applies the term, which DESIGN.md does not use yet.

## 3. Responses by theme

Each entry gives its sources, then its verdict and disposition, then what changed and where (new or changed ids in the text), then its tests. "T6" refers to the storage-tier redesign of section 3.6, which replaced parts of several T1 resolutions. Each entry describes the mechanism the text now holds. Its last line, *Final*, gives the second-round panel's status (section 1) and the new issues of section 6.2 that touch it.

### 3.1 Storage commit protocol (T1)

**T1-01. The head was not the only write that decided a push.** R3 C1; R3b finding 1, before-M2 1; R1b invariant 1; CRITIC4 §5. *Partly valid; fix-modified.* The "overwrites the entry" trace does not occur as written, but "remove what step 5 wrote" could delete a winner's dependencies.
- *Changed:* in §11.8's write rules, only the head If-Match decides. Other families are create-only, except the fences `repo/` and `slot/`, and `idx/`, a cache that only folds of committed versions write (§11.7). I-EVS-1 to I-EVS-7 are new; D-EVS-13 and §3.7 F2 change to match.
- *Not adopted:* R3b's immutable per-push entry objects. A head read would then need a LIST or a whole-ref manifest, against owner decision 2's 2-3 GET read.
- *Tests:* FS-1, FS-2, FS-57; TLC on `EvsCommit.tla`.
- *Final:* fixed (owner decision 148; rounds 5-6): 5g reads entries after the head and keeps that head's horizon, and removal folds now write versioned tombstone markers with If-Match, never blind deletes, so no late or redundant fold deletes an entry a later fold wrote (ST-N1; section 6.2). The batch records a head names by push id and place are the panel's accepted equivalent of R3b's per-push objects.

**T1-02. Uncertain head-CAS outcomes entered cleanup, and retries could not find their commit.** R1 F08; R1b F06, invariant 2; R2 F07; R3 C1; R3b finding 1. *Valid; fix.*
- *Changed:* §11.8 Outcomes (D-EVS-23):
  - A push id names one statement. Its retry returns the original version from the window or the log pages of (b, b+64].
  - No answer deletes anything. A dead push's record and slots go only through evacuation's Resolve.
  - Every refusal rests on a cluster read of the head. A refusal from a check outside the head first raises the ref's fence.
  - An unknown outcome reissues the identical PUT only within 5 s of step 4.
- *Tests:* FS-1 (a lost response, 65+ commits, concurrent retries, a fenced refusal), FS-57, FS-62.
- *Final:* resolved. New: SC-N1 (major; resolved), SC-N3 and SC-N4 (fixed).

**T1-03. Pending versions could evict the committed version of a path.** R1 S01; R1b S02, invariant 6. *Valid; fix, as amended by T6.*
- *Changed:* index entries hold only committed versions, written by lazy folds (§11.7; D-EVS-31). Pushes write nothing to `idx/`, so no pending version exists to evict anything. A path's newest committed version is its folded entry or a newer window version. Reads, listings and the path-level CAS all use that rule (I-EVS-4, I-EVS-6; §2.8 evs-11). T1's cap of four pending versions and PATH_BUSY are gone.
- *Tests:* FS-7, FS-58.
- *Final:* resolved. The lazy-fold rule it adopted had ST-N1, now fixed (owner decision 148; rounds 5-6; section 6.2).

**T1-04. Orphan GC could not find never-logged uploads, and raced publication.** R1 S03; R1b S03, invariant 6; R2 F10; R3 major "GC and quotas" (GC half). *Valid; fix-modified (receipts and evacuation instead of a history walk).*
- *Changed:*
  - Every push, part and seal is a record in a minute-bucketed batch that hourly evacuation resolves, so orphan pushes are found without the log (§11.13; D-EVS-25).
  - A segment upload writes nothing to the metadata cluster and returns a MAC'd receipt that the push presents (§11.13 Uploads; D-EVS-34).
  - GC deletes an unadopted segment only after 25 h, a fence on each idle ref and a second check (I-EVS-5).
  - T1's `up/` markers were withdrawn (§2.8 evs-20).
- *Tests:* FS-8, FS-59, FS-60.
- *Final:* resolved. New: OT-N5 and SL-N6 (fixed).

**T1-05. Path-level landing broke git ref semantics, multi-ref pushes and crash publication.** R1 F07; R1b F09; R2 F08; R3 C2; R3b finding 1, before-M2 1; CRITIC4 Major 1, Q1. *Valid; fix. Owner decision 141 confirmed the model.*
- *Changed:* refs take a mode at creation (§11.7).
  - Git-mode refs commit only on their tip, every push included. A lost race is a stock non-fast-forward, export keeps exact oids, and readers check TIP, descent and the committer.
  - File-mode refs keep disjoint landing.
  - The local tier publishes through proc-receive with per-ref statuses and a journal (§11.11; D-EVS-22, D-EVS-28).
- *Not adopted:* landing plus an automatic merge push (CRITIC4). The tip stays undefined until the merge lands, and sidecar/market2.md:519-520 forbids automatic merges.
- *Tests:* FS-5, FS-1, §22.7 S2.
- *Final:* resolved. New: SC-N1 (major; resolved).

**T1-06. The revocation gate did not fence the commit.** R1 F09; R1b F07, invariant 3; R2 F19. *Valid; fix (with T2-01).*
- *Changed:* the gate object left `repo/`. Statements declare an AuthPin and a generation pin. Step 7's If-Match commits only if the pins satisfy §10.6's predicate against the newest state and do not fall below the head's (§11.8 Gate; D-EVS-18).
  - Step 7 must follow step 4 within 5 s. New refs and deposits take the same check.
  - §10.6 publishes the in-flight window: about 10 s (5 min if api's notification is lost), plus the store's request deadline.
- *Tests:* FS-3; §22.7's revocation suite.
- *Final:* resolved. New: SC-N6 (fixed).

**T1-07. Path-key migration had no complete snapshot, no stale-writer fence and no overlap rule.** R1 F10; R1b F08; R2 F09; R3 major "Path tokens …" (rotation). *Valid; fix.*
- *Changed:* §11.6's path-epoch state machine (D-EVS-12).
  - A member-device removal or a compromise makes an epoch due at once. In general, config and mailcfg repos, creations then wait for the map (412 PATH_EPOCH_DUE).
  - The map binds its source version and chain and is keyed by its hash. The head's path epoch fences stale writers, parts and seals.
  - Up to three source epochs overlap under one copy job, and lease holders re-subscribe.
- *Residual (§11.20):* with no capable mapper online, creation stays blocked, and writers alarm after 1 h.
- *Tests:* FS-4.
- *Final:* fixed: a path tail and a creation block of at most 2 min let every epoch land, batched epochs alarm 1 h past due, and D-EVS-12 reads "due within 24 h" (SL-N3); the copy now handles directories a fold moved (SL-N2, re-checked resolved; its checker's follow-ups fixed in round 4; section 6.1).

**T1-08. The token, name and ref-id derivations were underspecified.** R3 major "Path tokens work for a client that already knows the path" (derivations). *Valid (t_0 was already defined); fix.*
- *Changed:* §11.6's Tokens block fixes:
  - name bytes as raw git bytes;
  - K_path_p and K_ref by HKDF with stated labels;
  - ref_id = HMAC-SHA256(K_ref, "ref" || name)[:16];
  - one token per path per epoch across a repo's refs, which §2.8 evs-2 and evs-11 now publish.
- *Tests:* §22.5's §11 row (token vectors; NFC and NFD names are two paths; any reader derives `main`'s ref id).
- *Final:* resolved.

**T1-09. A lifetime ref key lets a removed member test future branch names.** R1 S04; R2 F18. *Already fixed; disclose.*
- *Why no change:* per-generation ref ids would make every name lookup probe one key per generation. We also said random ids would need a catalog with the same exposure; the panel showed that a catalog sealed under the current generation would hide post-removal names, so that reason does not hold.
- *Disclosed:* §11.5's token-leak bound and §2.8 evs-2 say that a holder of RK_1 can test guessed branch names for the repo's life.
- *Final:* disclosed.

**T1-10. Head readers could not bind the file they were served (Q-EVS-6).** R3 and R3b majors and Q-EVS-6 answers; R1, R1b and R2 Q-EVS-6; R3b before-M2 6; CRITIC4 Major 3, Q3. *Valid; fix-modified.*
- *Changed:*
  - Statements of at most 1 KiB live in log pages (D-EVS-24).
  - The head's 64-byte window entries name each recent statement's hash and place (D-EVS-29).
  - The read reply carries every statement after the reader's pin and the one behind each served entry. Head readers verify the signers, the chain, the entry hashes and every later change (§11.9).
- *Disclosed (§2.8, §11.9):* a never-read path's version at the first pin rests on evs. A HeadCheck confirms the pin, not that version.
- *Not adopted:* a Merkle root over the token tree, or a whole-ref manifest.
- *Tests:* FS-10.
- *Final:* disclosed. §11.17's closure no longer ends "Residual: none": a HeadCheck confirms the pin, not a never-read path's version, and that limit is its residual (SC-N7, fixed). New: SC-N5 and OT-N8 (fixed).

**T1-11. v0 witnesses did not compare ordinary ref heads.** R1 F02; R1b F05. *Valid; fix (with T2-07).*
- *Changed:* HeadCheck carries up to 16 RefHead pins a round, rotating, defined once in §6.5. The side at the lower version recomputes C forward from the window's statement hashes or the log pages (§6.4; §11.8's witness rule). This ships at M2, so I-16 holds for ordinary refs. EvsHeadCheck is withdrawn, and 0x1402-0x1403 stay reserved (§6.11, §11.19).
- *Tests:* FS-17.
- *Final:* resolved; FS-17 lacks an independently advanced, non-conflicting case.

**T1-12. A restore could win after irreversible slot deletion.** R1 F11; R1b F10, invariant 5; R2 F12. *Valid; fix.*
- *Changed:* §11.12's deletion state machine (D-EVS-19):
  - The device files RepoDelete or RepoRestore into the access log first (§8.8), and evs takes `deletion_id` and `now` from that statement.
  - Restore is legal only from `deleted`.
  - A terminal `shredding{deletion_id}`, taken by If-Match, precedes any key destruction.
  - Each phase rereads the state and the deletion id, so a stale job deletes nothing.
  - A re-seed refuses a repo whose log ends in RepoDelete (§19.10).
- *Tests:* FS-6; §22.5's §11 row.
- *Final:* resolved. New: SC-N6 (fixed).

**T1-13. Erasure left decryptable deposit, index and retained copies.** R2 F11; R3 major "GC and quotas" (erasure); R1b C06. *Valid; fix.*
- *Changed:*
  - Erasure is a committed ERASE push on the repo's `erasure` ref. It names every key of every representation: retained versions, derived-field chains (re-checkpointed under a fresh key) and an unconsumed deposit's slot (§11.12; D-EVS-26).
  - Deposits are slot-keyed, so CONSUME or erasure removes the key (§11.6, §15.7).
  - Readers and mirrors delete cached keys, slot copies and decrypted copies on the hint (§15.7, §16.8).
- *Stated limits:* v0 erasure is key destruction. Ciphertext stays in batches, packs and segments until v1's compaction, and statements stay.
- *Tests:* FS-13; §22.5's §11 row.
- *Final:* resolved. At the storage limit an erasure's CLOSURE push passes within its eraser's own daily closure allowance, which §21 cannot cut below its floor, and §11.13 and §15.7 state the wait (SL-N1, now fixed: owner decision 146; rounds 5-6; section 6.2).

**T1-14. Mirrored recovery and cluster-only slots contradicted each other.** R1 F18; R1b F11; R2 C03. *Valid; fix (with T5-05).*
- *Changed:* §11.13's mirror contract (D-EVS-17):
  - A full mirror holds every object a committed push names, and slots as wrapped bytes.
  - It applies each erasure before its next sync, and keeps its ERASE pushes for 30 days. `ur status` reports coverage.
  - Re-seeding uploads ERASEs first and slots last. Readers accept a head below their pin only under an EvsReseed (§11.6, §19.10).
  - Erasure is immediate on the cluster and reaches mirrors at their next sync (§19.6, §10.8).
- *Residual (§2.18):* a stale mirror returns an erased key only if no surviving device holds the ERASE.
- *Tests:* FS-41.
- *Final:* resolved; FS-41 does not crash during a re-seed. New: SL-N5 (fixed).

**T1-15. GC and quotas could not see the bytes they account.** R3 major "GC and quotas" (accounting); R1b S03; R2 C04 (producers). *Partly valid: locators were bound to `entry_sha256`, but no rule said evs checks it. Fix.*
- *Changed:*
  - evs checks every entry version, change list and payload list against the signed statement (§11.6).
  - A repo's stored bytes are the sizes of its `seg/`, `pack/` and `hp/` objects, plus the record lengths its heads and log pages give for versions still in batches. The count runs nightly, and usage batches with retry identities move it between passes (§11.13 Quotas; D-EVS-16; §20.6, §20.7).
- *Tests:* FS-47, FS-60 (FI-13(c)).
- *Final:* resolved. New: OT-N5 (fixed).

**T1-16. Maintenance pushes were blocked at the storage limit.** R1 C02 (quota exceptions); R1b C05. *Valid; fix (with T5-12).*
- *Changed:* at the limit, and while spent, evs refuses only pushes that name a new segment or inline record.
  - Maintenance pushes pass: CONSUME, BASE, ERASE, PATH_EPOCH and its maps, DELETE, deletion, restore and re-seed.
  - So do config and mailcfg pushes within §7.9's limits (§11.13 `limit`; §20.7).
- *Tests:* FS-47.
- *Final:* fixed (owner decision 146; rounds 5-6): an erasure's CLOSURE push and its uploads pass at the limit, and §11.13 and §20.7 agree on uploads (SL-N6, fixed); the closure allowance is now per eraser, with a floor §21 cannot lower, §11.12, §11.13 and §11.19 state it and its 429, and FS-47 queues a CLOSURE past the rate as P1, as §11.12 does (SL-N1; section 6.2).

**T1-17. The directory cap did not fit the entry size.** R1b S04. *Valid; fix.*
- *Changed:* a directory holds at most 4,096 children and 448 KiB of name table. Both are checked at push time against the folded table plus unfolded deltas (409 DIRECTORY_FULL), and `layout` reserves paging (§11.7; §2.8 evs-11; §11.18).
- *Tests:* FS-9.
- *Final:* resolved. New: SL-N7 and SC-N2 (fixed).

**T1-18. A lease and its counter were separate writes.** R1b C07. *Valid; fix, as amended by owner decision 136.*
- *Changed:* leases are Redis soft state (§11.10; D-EVS-14; §2.8 evs-8).
  - One script writes the lease and raises `{evsl_<repo_id>}v` before the 200.
  - The holder rereads the head from the cluster 5 s after the 200, never from the head cache.
  - After a Redis loss, holders re-create their leases at their hourly resync.
- *Tests:* FS-12, FS-62.
- *Final:* resolved.

**T1-19. A cached negative pack lookup could miss a packed object.** R1 C02 (packing races); R1b C11. *Valid; fix.*
- *Changed:* a reader whose cached `pidx/` or `spidx/` lookup misses, and who then gets 404 on the original, drops the cache and lists again. A pack precedes its index entry, and both precede the original's deletion, so one retry finds the object (§11.13 `negative`).
- *Tests:* FS-11.
- *Final:* resolved.

**T1-20. Locators would have frozen without a pack address (Q-OPS-2).** R3 major "Q-OPS-2 should not freeze the locator"; R3b Q-OPS-2, before-M2 6; R1, R1b and R2 Q-OPS-2; CRITIC4 Q9. *Valid, with one invalid sub-claim (T5-32); fix.*
- *Changed:* locators sit inside signed entry versions and can never be rewritten. So format 1 addresses segments by content id only, reserves the `spidx/` family and its lookup order, and reserves locator kinds 3 and 4 (§11.6; D-EVS-27; §2.8 evs-21). Q-OPS-2 is closed as (b), with (a) as a switch (section 5).
- *Tests:* §22.8's `hdd` row (T5-29).
- *Final:* fixed: `gen/` takes §10.16's gen packs at §19.9's gen trigger, and they count as `gen/` for shreds and re-seeds (section 6.1). New: OT-N4 (fixed).

**T1-21. Small repos' push logs never left NVMe.** CHECK4 minor 7. *Valid; fix, superseded by owner decision 136.*
- *Changed:* hourly evacuation packs a repo's records and log pages older than 24 h once they reach 256 KiB. Below that they go to NVMe parcels that pack within 7 days (§11.13; D-EVS-32; §19.9; §2.8 evs-12, evs-16, evs-23).
- *Tests:* FS-53, FS-60.
- *Final:* resolved, as owner decision 136's packing.

**T1-22. A compromised recovery code kept deriving the path key.** R1 F06; R1b S01. *Valid (narrow); fix (with T2-12).*
- *Changed:* a compromise retirement (a SidecarRevoke or RecoveryRebind with reason `compromise`, agents included) makes a path epoch due at once (§11.6 `due`). Checkpoint rule (4) fires on it, and every checkpoint draws a fresh object key (§11.7).
- *Tests:* FS-22.
- *Final:* fixed: §10.8, §7.9 and §5.9 say that no rebind reaches a keychain backup sealed before it, and that each device whose backups may be exposed is revoked as compromised and enrolled anew (section 6.1). Related: AU-N2's keychain.wrap gap, now fixed: a cascade's void re-seals keychain.wrap, and the backup rule covers a voided binding (owner decision 149; rounds 5-6).

**T1-23. Repo-wide hint topics used per-ref counters.** R1 S02; R2 F17; R3 major "Head readers cannot bind …" (last sentence). *Already fixed: the push sequence versions the topic per repo. Decline.*
- *Changed:* one clause. The delta's ref version against the client's pin shows a gap on that ref (§11.10). The sequence now lives in Redis and restarts above every earlier value after a loss.
- *Tests:* FS-62.
- *Final:* resolved; the stated residual is a crash before the raise, left to the hourly resync.

**T1-24. Inline bodies in one buffered POST exceeded the load balancer's 16 MiB.** R3 C2 (third paragraph). *Already fixed: pushes over 1 MiB or 1,024 entry writes travel in parts (D-EVS-20). Decline; no change.* *Final:* resolved.

### 3.2 Authority and keys (T2)

**T2-01. Authorization state needed a delta-prefix commitment and a causal revocation identity.** R1 F01; R1b F01, F02 (in part); R2 F03, F04 (in part). *Valid; fix.*
- *Changed:* one hash-chained authorization log per network (§7.9; D-TEAM-19).
  - Position n is the projection version, and A_n is the chain digest. Every consumer carries AuthPin (n, A_n): EvsPush, EvsHead, GkmCommitHeader, GenRotate, approvals, HeadCheck and BridgeState.
  - Bases commit to what they fold and never fall, and retention keeps what they re-apply.
  - Shrinks get a positional identity and expiries a time identity, which §10.6's gate predicate compares.
  - D-TEAM-17, D-ACL-16 and D-KEYS-3 change to match.
- *Tests:* FS-14; §22.7's admission and revocation suites.
- *Final:* resolved; FS-14 lacks a RepoRevoke, an OwnerConfirm and a rotation covering one of two same-base removals. New: AU-N4 and AU-N6 (fixed).

**T2-02. Two paths raised a generation, and nothing serialized them.** R1b F02, invariant 4; CHECK4 major 2; CRITIC4 Major 5, Q5. *Valid; fix.*
- *Changed:* `gkm/<group_id>/gen/<g>`, created If-None-Match, is the only place a generation exists (§10.6; D-KEYS-15).
  - A rotation stages its wraps, then claims `gen/<g+1>`. An uncertain outcome resolves by reading the claim.
  - MLS commits never raise the generation; they carry the newest GenWrap. `ur_group` loses its generation fields.
  - A leaf rotator puts one LeafWrap in the GenRotate. A removal is a Remove commit, then an independent rotation (§10.5, §10.7, §10.9). D-KEYS-6 changes to match.
- *Tests:* FS-15; the TLA+ model's `gen/` claims.
- *Final:* resolved.

**T2-03. Delegation reader keys had no object, check or reap rule, and a dropped writer could sample the next generation.** R3b finding 4, before-M2 4; R3 "Q-ACL-9 (a) breaks removal"; R1 Q-ACL-9 note; CHECK4 major 1; CRITIC4 Major 4, minor 7. *Valid; fix.*
- *Changed:* §10.5 defines KeyHolders (leaves, uncovered agents, live Delegations and recovery keys), and DelegationWraps with their writers, checks and a Drops table (D-KEYS-16).
  - A covered agent's reap changes no holder set: no gate, rotation or path epoch.
  - DelegationRevoke, `not_after`, or a non-reap revocation of one of its agents drops a Delegation's key.
  - Every GenRotate is signed by a current holder and excludes the dropped key.
- *Tests:* FS-18.
- *Final:* resolved: any holder at a covering pin may sign, which gives R3b's member-leaf property under owner decision 114.

**T2-04. A reaped Delegation-admitted agent reads later generations until DelegationRevoke.** R3b finding 4; R3, R2 and R1 Q-ACL-9; R1b; CHECK4 major 1; CRITIC4 Major 4, minor 9, Q4. *Accepted residual (owner decision 114); disclose.*
- *Why it stays:* no individually revocable key lets an agent read before any writer is online, and that is the decision's purpose. The old per-reap rotations excluded nothing a reaped agent could not still read.
- *Disclosed* alike in I-15, §2.6, §2.10, §2.18, §3.6, §7.18, §10.5, §11.5 and §16.9.
- *Bounds:* `not_after` of at most 90 days (30 for CI), and a key drop on any non-reap revocation of its agents.
- *Reviewers split:* R1b accepts the shared key; R2 and R3 asked for individual keys.
- *Tests:* FS-18.
- *Final:* disclosed, alike in §10.5, I-15, §2.6, §2.10 and §2.18; §16.9's wording, which could be misread, now names the key's drop causes (AU-N9, fixed); the decline of individual keys holds.

**T2-05. The published 72-hour bound did not hold against a splitting server, an offline revoker or own groups.** R3 C5; R3b finding 2, before-M2 2; R1 F03; R2 F05; R1b F03; CRITIC4 Major 2, Q2; CHECK4 minor 8. *Accepted residual (owner decision 129), with valid text contradictions; disclose.*
- *Changed:* §2.8 publishes one bound, naming the split, the offline revoker, own groups, personal networks and the pilot. Every restatement cites it, and §6.17 rates the split Medium.
- *Declined:* R3's and R3b's quorum witness. Owner decision 129 chose any single admitted reader, and T2-06 makes that rule as strong as it can be.
- *Tests:* FS-21; §22.7's revocation suite.
- *Final:* fixed (owner decision 147; rounds 5-6): §2.8 now publishes the 8-hop relay bound that §6.4 delivers, and Q-TRUST-9, D-TEAM-17 and §8.7 match the residual (WR-N3, fixed); phones keep their newest 64 KiB of authorization-log entries and serve proofs, as §7.9's retain row says and FS-17 now expects (WR-N1; section 6.2). The quorum decline holds.

**T2-06. Witnesses had no path under policy, stale peers counted, and proven withholding waited.** CRITIC4 Major 2, Q2; R3 C5; R3b finding 2; CHECK4 minor 8. *Valid; fix-modified: one consistent witness stays, and the immediate stop applies only to verified proof.*
- *Changed:*
  - Control contracts carry only Hello, Ping and HeadCheck between any two admitted sidecars, and providers deny IP on them. They ship at M4 (§8.10; D-PROTO-18).
  - A witness counts only if it holds the same pin after reconciliation.
  - Verified withholding, or a FORK, stops sealing at once.
  - Rounds include other members' peers.
  - The revoker shows "unwitnessed" until a peer holds its position (§6.4-§6.6, §7.10; D-PROTO-17; D-TRUST-10).
- *Tests:* FS-17, FS-21.
- *Final:* fixed (owner decision 147; rounds 5-6): a peer holding a proof now sends `proven` and never counts as a witness, and an unverified higher pin is relayed and alarms (WR-N2, fixed); a phone holder serves the proof from its newest 64 KiB of entries, so the writer stops at once (WR-N1; section 6.2).

**T2-07. v0 HeadCheck compared no ref heads and no generations.** R1 F02; R1b F05; R3's head-reader major. *Valid; fix (with T1-11).*
- *Changed:* the RefHead and GenHead lists ship in v0, at most 16 each per message, rotating, with a reconciliation rule (§6.4-§6.5; D-PROTO-17).
- *Tests:* FS-17.
- *Final:* resolved.

**T2-08. The recovery veto had no signed protocol, and recovery had no pre-admission bootstrap.** R1b F04; R1 F04; R2 F06; R3 "The authority grammar already crowns one recovery key"; R2 Q-TEAM-10/11; CHECK4 major 3. *Valid; fix.*
- *Changed:* §7.9's recovery window (D-TEAM-21).
  - A statement with a recovery-key signature stays pending and delivers no key. It activates at an api tick 72 h after its newest such signature, unless any admin device has filed a valid RecoveryVeto, by appending it or by gossiping it in HeadCheck.
  - A rebind, an AdminSet change, the subject's removal or 7-day expiry voids it, and devices raise `recovery_unseen`.
  - Before admission, a code-only device reads only the log and its recovery wraps (§7.8, §10.14).
- *Tests:* FS-16; §22.7's admission suite.
- *Final:* resolved. "Delivers no key" holds for the proposed device only, as D-TEAM-21, §2.6 and §2.10 now say: with the operator's ciphertext a code holder reads the recovery wraps at once (WR-N4, fixed). New: WR-N5 and WR-N9 (fixed).

**T2-09. All-devices-lost recovery failed after the lost leaves were revoked.** R1 F04; R1b's disposition of it. *Partly valid: the self-join-first order was already in §10.8. Fix.*
- *Changed:* a recovery self-join may leave revoked leaves in the tree if it carries no GenWrap (generation 0). gkm accepts that epoch, and the device's next commit removes the leaves (§10.8, §10.9, §10.6).
- *Tests:* FS-20.
- *Final:* resolved. New: WR-N7 and WR-N9 (fixed).

**T2-10. k-of-n statements had no wire form, signed bodies were untyped, and approvers did not sign GrantActivate.** R1 C02; R1b C02, C11; CHECK4 major 3. *Valid; fix.*
- *Changed:*
  - `Signed.type` (field 6) is signed as u32be after the purpose, and verifiers parse a body only as its registered type (§6.9, §6.11; D-PROTO-7).
  - Log statements carry a StatementHeader with replay rules. k-of-n statements are an AuthorityProposal plus AuthorityCosigns (§7.9; D-TEAM-20, D-TEAM-21).
  - GrantActivate embeds the approvers' decisions and is accepted once per `grant_id` (§8.8).
- *Tests:* §22.6's cross-type matrix; §22.7's approval suite.
- *Final:* resolved. New: AU-N4 (fixed).

**T2-11. With `self_admit` off, a recovery code no longer restored the member's own repos.** CHECK4 major 4. *Valid; fix.*
- *Changed:* owner decision 112's switch covers only device-signed self-admission. A recovery-key admission completes on its own, or with one admin's cosign while `self_admit` is off (§7.9 `scoped`; §5.6; D-TEAM-16).
- *Tests:* §22.7's admission suite.
- *Final:* resolved.

**T2-12. Replacing a compromised recovery code left its path key in use.** R1 F06; R1b S01. *Valid (narrow); fix (with T1-22).*
- *Changed:* RecoveryRebind gains a reason: routine, lost or compromise.
  - A `compromise` rebind counts as a shrink though the holder's identity stays, so `holders_shrunk_at` advances. Its rotation is cause REMOVE, and a path epoch starts at once (§7.9, §10.8, §11.6).
  - `ur keychain recovery-rotate --compromise` signs it (§5.9).
- *Tests:* FS-22.
- *Final:* fixed, as T1-22.

**T2-13. Ephemeral deposit-only access conflicted with the effective policy.** R1 F05; R1b F03. *Valid; fix.*
- *Changed:* device classes apply before subject expansion. An ephemeral subject's evs access is capped inside `allowed` at grants that name it, kind-default deposits and EvsShares to it. `autogroup:ephemeral` is new, and ephemeral devices get no consent (§8.4-§8.6, §7.7; D-ACL-19).
- *Tests:* FS-19.
- *Final:* fixed: the ceiling passes the config kind default's read row, so every ephemeral sidecar reads the config (AU-N1, re-checked resolved), and FS-19 adds the invite, quick-burner, admin, tag, Delegation and add-then-remove runs, gated by feature in round 4 (section 6.1).

**T2-14. The projection the gates enforce differed from the policy the client evaluates.** R3 major "The id-only projection is not the policy the client evaluates". *Partly valid: the two-network intersection and members' default `evs:*` are by design. Fix.*
- *Changed:*
  - `autogroup:untagged` has one definition; untagged sidecars are `autogroup:member`.
  - When `has_document` is false, the implicit document is compiled into the rows, so gates and clients evaluate the same rows.
  - `allowed` runs over rows(t), and §8.11 states a share's two halves.
  - evs and gkm honor a scope only while its subject is a current reader or writer (§8.4-§8.6, §8.11, §8.12; D-ACL-20, D-ACL-21).
- *Tests:* FS-14 (a subject a group edit drops gets 403 within 5 s); §22.7's one-definition vectors.
- *Final:* resolved; both declines hold. New: AU-N5 (fixed).

**T2-15. Every admitted sidecar reads the member directory and K_sock.** R3 identity major. *Accepted residual (owner decisions 6, 67); disclose.*
- *Why it stays:* keeping K_sock or emails from agents needs a second readership of config data, which owner decision 6 rules out.
- *Disclosed:* §2.6 and §7.9 now say that CI and cloud agents read the policy, the AdminSet, any emails in policy text and K_sock. We also said the console may write `member:<id>` selectors to keep emails out of policy text, but §8.4 has no such selector.
- *Final:* disclosed. R3's ask to store group members as member ids is unaddressed.

**T2-16. JIT provisioning linked a pre-registered email.** R3 identity major. *Valid; fix.*
- *Changed:* identity is (idp_id, sub). An existing user is linked only after it completes a login with its existing credential in the same flow, never by email alone (§7.6; D-TEAM-23; D-TEAM-4 changes to match).
- *Tests:* §22.7's JIT case.
- *Final:* resolved.

**T2-17. The first-device consent path was defined three ways.** CHECK4 minor 5. *Valid; fix.*
- *Changed:* one `consented(d, M)` predicate lives in §8.5, and §5.6 and §7.9 cite it. A JIT member's first device enrolls from the invite that the admitting admin device issues (§7.6; D-ACL-22).
- *Tests:* §22.7's owner-consent cases.
- *Final:* not re-checked.

**T2-18. A stolen device's self-admissions survived its revocation (Q-TEAM-10 (a)).** R3 identity major; R2 Q-TEAM-10/11. *Partly valid: the verifier limits R3 asked for were already in §7.9. Fix.*
- *Changed:* `SidecarRevoke{reason, since_ms}`. A `compromise` revocation parks every admission and OwnerConfirm the device signed since `since_ms`, until an AdmissionConfirm or a fresh OwnerConfirm (§7.9; §2.10; D-TEAM-26).
- *Tests:* §22.7's cascade case.
- *Final:* fixed (owner decision 149; rounds 5-6): the cascade parks the closure from `since_n`, a log position (AU-N3, fixed), and voids the RecoveryBinds, Rebinds, KeyRegisters and EvsShares it signed; a void now re-seals keychain.wrap and re-enrolls devices whose backups hold the voided sealing, and a binding a void restores admits only by a recovery AuthorityProposal, through the 72 h window with admin veto (AU-N2; section 6.2).

**T2-19. A depositor could not tell a fresh drop key from a stale one.** R2 F04. *Valid; fix.*
- *Changed:* the drop key moves into the generation's signed GenRotate, which carries its auth pin and time. Depositors, who read the config, accept it only if the generation covers every shrink and expiry they know, and they pin it. DropKeyStatement is withdrawn (§10.5, §11.12; D-KEYS-17; D-KEYS-8 changes to match).
- *Tests:* FS-23.
- *Final:* resolved. New: AU-N11 (fixed).

**T2-20. A deposit-only principal could not fetch the drop key.** R1 S06; R1b S06; R2 F06 (deposit half). *Valid; fix.*
- *Changed:* `GET /gkm/groups/<id>/drop-key?since=<g>` accepts the deposit scope, which reaches nothing else, and returns the newest GenRotate plus up to 64 after `since` (§10.6, §10.14; D-KEYS-17).
- *Tests:* FS-23.
- *Final:* resolved; §10.6's scope sentence, which read literally voided the deposit scope, now names r, rw and admin scopes (AU-N5, fixed). New: AU-N11 (fixed).

**T2-21. Small groups' GroupInfo was not crash-safe with its commit.** R1b C04. *Valid; fix.*
- *Changed:* at 16 leaves or fewer, the epoch object carries the sealed GroupInfo, and `group-info` is a pointer rewritten every 16th epoch and at each Add. Above 16 leaves, a self-join waits for a leaf online (§10.5, §10.6, §10.8; D-KEYS-18). T6 adds that a GroupInfo above 16 leaves is written at most once per epoch, on request (D-KEYS-21).
- *Tests:* FS-20.
- *Final:* fixed: KF1 writes a repo's first RecoveryWraps before activating it, any commit 16 or more epochs past the `group-info` pointer heals it, and FS-20 kills both boundaries (WR-N7; section 6.1).

**T2-22. gkm's work hints were dropped as stale, and rotations without a commit went unhinted.** R1b S05; R1 S02 (last sentence); CRITIC4 Major 5. *Valid; fix.*
- *Changed:* `gkm:<group_id>` is versioned epoch × 2^24 + generation. Pending and wrap-pending hints go on the per-client `gkm` topic of the sidecars that must act, versioned by gkm's clock (§6.8, §10.6, §10.14; D-KEYS-19).
- *Tests:* FS-24.
- *Final:* resolved. New: AU-N10 (fixed).

**T2-23. Epoch retention could delete the predecessor of the next commit.** R2 F16; the Q-KEYS-11 answers of all five reviews. *Valid; fix.*
- *Changed:*
  - The newest epoch is never deleted, and the `group-info` pointer moves first.
  - Generations, GroupInfo and recovery wraps live outside epochs.
  - A preservation hold pauses the sweep.
  - Acks are Redis soft state (owner decision 136), and the reconciler deletes only while the ack family has existed 30 days (§10.6; D-KEYS-20, D-KEYS-21).
  - Q-KEYS-11 is closed (section 5).
- *Tests:* FS-62; §22.5's §10 row.
- *Final:* resolved; the resync half of R2's acceptance has no test.

**T2-24. The key ladder overstated post-compromise security and post-quantum protection.** R3 cryptography majors; R3b ladder major, before-M2 7; CRITIC4 minor 5. *Valid; fix-modified.*
- *Changed:*
  - D-KEYS-1 claims tree post-compromise security for KEKs only; content keys heal at the next generation.
  - R-KEYS-12 claims harvest-now-decrypt-later resistance against a passive adversary only.
  - §10.5 states the ladder's limits. §2.10 and §2.18 disclose copied keychains and a future signature forgery.
  - `ur evs rekey` moves to v0 (M2) (§10.16, §11.21).
- *Declined:* rotating the root key on every Update. A 1,000-leaf group would get about 33 generations a day, with old content left under old keys anyway. Hybrid ML-DSA authority signatures are Later.
- *Tests:* §22.7's revocation suite (after `ur evs rekey`, only the current generation opens).
- *Final:* fixed: Q-KEYS-2 now states its residual (WR-N3; section 6.1). The decline of rotation on every Update holds. New: WR-N6 (fixed).

**T2-25. M2's 0x0010 gate interoperated with no second stack.** R3 cryptography and internal-gates majors; R3b ladder major, before-M2 7. *Valid; fix (with T5-22, T5-23).*
- *Changed:* the MLS wire's fields are fixed at M2's entry. The wire and suite 0x0010 freeze at M2's exit on §22.10's interop artifact:
  - X-Wing KATs for Go's MLKEM768X25519;
  - a two-way, 10-epoch lifecycle against tmc/mls with equal exporter outputs;
  - GenWrap, LeafWrap and GenLink reproduced by `mlsinterop/`.

  Sources: §10.4; D-KEYS-10; §23.4; §23.8.
- *Tests:* the 0x0010 interop artifact.
- *Final:* resolved. New: WR-N8 (fixed).

**T2-26. Native IP authorization trusted operator-minted subject claims, and C13 did not say what it seals.** R2 F01; R3 protocol major "C13 does not say which id is sealed". *Valid; fix (with T4-15).*
- *Changed:*
  - Each window client carries a customer-signed WindowDelegation, sealed into the contract by C13. The provider verifies it against the subject's pinned identity key before opening any upstream socket.
  - C13's sealed subject, network and class become consistency checks.
  - Senders check target keys against the target's identity binding.
  - Shares use a ShareKey that the other network pins (§17.6, §17.8, §17.9, §8.10, §6.10.1, §4.6 C13; D-BRIDGE-17).
- *Tests:* FS-38.
- *Final:* resolved; before C16, sdk providers apply rules 4 and 7 to C13's operator-asserted subject, as disclosed. New: AU-N7 (fixed).

**T2-27. Unknown policy state selected allow-all.** R2 F02; R1 C04; R1b C10. *Valid; fix (with T3-08).*
- *Changed:* the bridge and the keyless device role share one state machine: legacy, pending, enforcing{doc} and enforcing{nodoc}. It persists the last verified state with a `document_seen_at` latch.
  - Pending denies private destinations, exits and served prefixes.
  - Owner decision 120's allow-all applies only once no-document is verified (§17.8, §18.6; D-BRIDGE-18).
- *Tests:* §22.7's unverified-state cases.
- *Final:* resolved.

**T2-28. A read-only browser device inherited its member's authority.** R2 C01; R1b S10. *Valid; fix (one field with T3-04).*
- *Changed:* `SidecarAdmit.capabilities` gains a `read_only` bit, which every verifier enforces (§7.9, §18.8, §16.6; D-TEAM-24). A read-only device:
  - signs only its own sign-out, its own leaf's path-only commits, resyncs, read receipts and HeadCheck replies;
  - never counts toward k;
  - is never approval-capable.
- *Tests:* §22.7's read-only Worker cases.
- *Final:* resolved.

**T2-29. Pre-approved auth keys carried client-only secrets with no wire split.** R1 F17; R1b C01. *Valid; fix (one design with T3-24).*
- *Changed:* the key format is `ur-authkey-<id>-<secret>#<bundle>`. The client splits off the bundle (genesis hash, head, a Delegation's signing and reader seeds) before any request. `POST /network/enroll` refuses an `auth_key` containing `#` and never logs it (§7.8, §5.6; D-TEAM-22).
- *Tests:* §22.7's auth-key cases; the privacy harness's Delegation-seed canaries.
- *Final:* resolved.

**T2-30. One root key could open every network's keychain.** R1 C02; R2 "Cross-network keychain separation". *Valid; merged into T3-15.* *Final:* resolved, as T3-15.

**T2-31. "Update" named an RFC 9420 proposal that a committer cannot commit for itself.** R1 C02 (MLS self-update). *Valid; fix.*
- *Changed:* self-update is a path-only commit (RFC 9420 §12.4), and Update proposals are refused (§10.4, §10.9).
- *Tests:* §22.5's §10 row.
- *Final:* resolved.

**T2-32. Remove grounds lacked a signed input.** CHECK4 minor 6. *Valid; fix.*
- *Changed:* §10.9's Remove row and §8.12 accept only grounds with a signed input: revoked, suspended, no longer reading, or past the signed `stale_leaf_days`. "Deactivated", an unsigned server state, is gone.
- *Tests:* §22.7's committers cases.
- *Final:* not re-checked.

**T2-33. The 1,001st member device of a network (Q-KEYS-15).** CRITIC4 minor 11. *Valid; owner item, decided by owner decision 144, which chose (b) over our recommended cap.*
- *Changed:* §7.9's `leaves` rule is the only definition, and §5.6, §8.12 and §10.4 cite it.
  - Live member devices rank by (live_since, sidecar_id), and the first 1,000 are config leaves. The rest read the config by ReaderWraps and stay leaves of their data repos.
  - A wrapped device commits no config Add or Remove.
  - A move shrinks nothing.
  - §20.4 has no member-device cap, and config wraps for devices past the first 1,000 ship at M6 (§10.12; D-ACL-17).
- *Tests:* §22.7's seat cases.
- *Final:* resolved. New: AU-N8 (fixed).

**T2-34. SCIM deprovisioning is not cryptographic removal until an admin signs.** R3 C5 (last paragraph). *Valid; disclose, with an opt-in signer.*
- *Disclosed:* until an admin device signs the queued MemberRevoke, members still encrypt to that member's devices. The console lists them.
- *Changed:* `ServiceSettings.scim_signer` may name an always-on admin daemon that signs such removals at once (§7.6, §7.9, §7.18; D-TEAM-25).
- *Final:* disclosed.

**T2-35. Site-loss re-forming of owner-bound groups had no named re-former.** CHECK4 minor 10. *Valid; fix (with T5-06).*
- *Changed:* repo admins' devices re-form groups. For owner-bound repos, only the owner's consented device does (§10.8; §19.10; D-KEYS-13).
- *Tests:* FS-41.
- *Final:* not re-checked.

**T2-36. Q-KEYS-12's summary said gkm never sees what external commits show it.** CHECK4 minor 9; R3 Q-KEYS-12 row. *Partly valid: the membership point was already fixed. Fix.*
- *Changed:* Q-KEYS-12 now reads "never, in a member commit, …; external commits show gkm-6's values". gkm-6 lists their ExternalInit and Remove proposals and UpdatePath keys (§10.12, §10.6, §2.8).
- *Final:* not re-checked.

**T2-37. §3 gave config-group Removes the wrong token scope.** CHECK4 minor 11. *Valid; fix.*
- *Changed:* §3.13 says the Remove and the rotation it requires run under the gkm `rw` scope that §7.8 gives member devices in the config group, following §7.9's leaves rule.
- *Final:* not re-checked.

**T2-38. The sdk mapped a transport-token rejection to identity revocation.** Merged into T3-13. *Final:* resolved, as T3-13.

**T2-39. The key-store API could not say "locked".** Merged into T3-14. *Final:* resolved, as T3-14.

**T2-40. The sandbox operator was outside the threat model.** Merged into T3-23. Its §2.6 addition stays. *Final:* disclosed, as T3-23.

**T2-41. Browser admissions need a consented device online.** CRITIC4 minor 6. Merged into T3-18, whose key-origin block states it. The quick burner waits for such a device. *Final:* resolved, as T3-18.

### 3.3 Runtime and approvals (T3)

**T3-01. Approvals were spent after their effect, not before.** R1 F20; R1b F12, invariant 7. *Valid; fix.*
- *Changed:* a use is reserved before its effect (§16.6 Consumption; §8.10; §12.8; D-MCP-11):
  - locally, by an fsynced Reserve in the daemon's ledger;
  - at a server gate, by an `approval_use` row written in the effect's own transaction and keyed by `Idempotency-Key: <effect_key>`.
- Every component is idempotent per effect_key and has a Lookup for each kind. A restart reconciles open reservations, and an uncertain use stays consumed. Cancel (`POST /approval/cancel`), expiry and k approvers are defined. D-MCP-4 changes to match, §2.8 api-10 adds the use rows, and §23.4's M3 exit requires the suite.
- *Tests:* FS-25; §22.7's approval suite (AU1-AU4).
- *Final:* resolved. New: RT-N3 (fixed).

**T3-02. A decision did not bind its requester, its authorization pin or a grant activation.** R1b C02; R1 F20; R1b F12. *Valid; fix.*
- *Changed:*
  - ApprovalDecision gains `requester_sidecar_id`, the approver's AuthPin and a version (§16.8).
  - Every spender runs §16.6's spend check: requester equality, a payload hash over stored bytes, expiry, the pin, and re-evaluation under its own pin.
  - GrantActivate embeds the decisions under a `grant_id` the approval fixes, so a replayed or revoked grant is refused (§8.6, §8.8, §3.7 F8; D-MCP-12).
- *Tests:* FS-29; the approval suite's `decisions` row.
- *Final:* resolved. New: RT-N6 (fixed).

**T3-03. Approval channels disappeared, or never existed, on supported hosts.** R1 S14; R1b S10. *Valid; fix.*
- *Changed:*
  - An approval-capable device is consented, untagged, not ephemeral and not read_only, on a host that signs decisions (§16.6's predicate and host matrix).
  - `device` evidence must come from such a device other than the requester.
  - Control mode signs it only for another sidecar's request, after a /dev/tty or app confirmation (D-SDK-9).
  - `harness_ok` counts only approval-capable devices (D-MCP-14; I-8 reworded).
- *Disclosed (§16.15):* two of a member's devices that both run agents can approve each other.
- *Tests:* the approval suite's `devices` row.
- *Final:* resolved.

**T3-04. "Read-only" browser Workers inherited full member authority.** R2 C01; R1b S10. *Valid; fix (one field with T2-28).*
- *Changed:*
  - Verifiers accept only a read_only device's sign-out, its own MLS maintenance, its receipts and its HeadCheck replies (§7.9).
  - The token exchange gives it only `r` scopes and the receipt deposit (§7.8).
  - Member devices' gkm `rw` excludes it, and gkm refuses its `gen/` claims (§10.6).
  - D-TEAM-24 is the decision; D-SDK-6 changes to match.
- *Tests:* §22.7's read-only Worker cases.
- *Final:* resolved.

**T3-05. Harness evidence was a hook any same-uid process could submit.** R3 C4; R3b finding 3, before-M2 3; CRITIC4 Q8, minor 8. *Valid; owner item, decided by owner decision 142 (Q-MCP-6 (c)).*
- *Changed:* §16.6 states that no binding to the harness binary is possible.
  - Harness evidence never authorizes key, recovery, consent, admission or authority statements, nor acl or bridge statements beyond an O tool's own filings, except a member's first presence key.
  - The daemon offers a presence prompt, and `ur login` offers a presence key.
  - In a tainted run, harness evidence counts only where the requests rule names it (D-MCP-9; I-9; §2.10, §8.5, §16.15).
- *Residual:* in untainted runs it stays a labeled weaker channel (owner decision 75).
- *Tests:* FS-28.
- *Final:* disclosed; §2.18 does not repeat the untainted-run residual.

**T3-06. Presence approval had no evidence profile.** R1 C03; R1b C03. *Valid; fix.*
- *Changed:* §16.6's profiles (D-MCP-19):
  - `webauthn-es256`, attested or asserted, with UP, UV, rpIdHash, challenge, origin and counter checked on every use;
  - Secure Enclave `ecdsa-p256-sha256` keys, labeled asserted.
- KeyRegister needs the new key's own presence proof and a device or presence decision, never harness evidence (§6.9, §7.9, §18.5). A member's first key comes from `ur login` or a confirmed terminal, as disclosed.
- *Tests:* the approval suite's `presence` row.
- *Final:* resolved.

**T3-07. Whole-tree scans misattributed changes, so restore could revert others' work.** R1 F19; R1b F13, invariant 8; R2 F14. *Valid; fix.*
- *Changed:* §16.7 (D-MCP-15; D-MCP-8 changes to match):
  - a local, exact restore point: HEAD plus sealed copies of the files dirty at start;
  - a per-path ledger of hook-time hashes, each change attributed as edit, shell or foreign;
  - restore writes only paths whose whole chain is this run's edits, rechecked against a `preview_id`;
  - shell-attributed paths are restored only when named after a dry run;
  - RV1-RV3 are its invariants.
- *Tests:* FS-26; §22.7's restore suite.
- *Final:* fixed: each edit observation carries a before-hash, a change counts as the run's edit only when the run's edits chain from the scan's before to its after, and the restore suite and FS-26 add a hand edit before the run's edit of the same path (section 6.1).

**T3-08. Run taint and the device role's policy did not survive restarts.** R1 C04; R1b C10, invariant 7; R2 F02, "Sticky run taint". *Valid; fix (with T2-27).*
- *Changed:*
  - Taint is a monotone, fsynced bit in the run's file, written before untrusted data leaves the daemon. A missing or unreadable file reads as tainted (§16.4, §16.6; D-MCP-16).
  - The device role restores enforcing state before its first packet and never reads an unverified projection (§18.6; D-SDK-13).
- *Tests:* FS-27; §22.7's unverified-state cases.
- *Final:* resolved. New: RT-N6 (fixed).

**T3-09. The tool catalog and CanonicalAction did not close the trusted action.** R3 runtime major. *Valid; fix.*
- *Changed:*
  - MCP's evs_write and evs_delete refuse config and mailcfg repos. MCP signs no authority statement, and only those acl and bridge statements about this sidecar's own resources that a §16.5 tool's approved action files.
  - Policy is signed only for a /dev/tty-confirmed command or an app UI (§5.8, §16.6).
  - CanonicalAction carries every field an O tool acts on, and approvers render only daemon-built fields (§16.8; D-MCP-17).
- *Tests:* the approval suite's `actions` row.
- *Final:* resolved. New: RT-N1 (major; resolved), RT-N2 and RT-N3 (fixed).

**T3-10. MCP results broke clients older than 2025-06-18.** R2 F24. *Valid; fix.*
- *Changed:* results leave `Content` nil, so go-sdk renders the tagged structured output as one TextContent for every version. Below 2025-06-18, an over-limit result names its `ur://` resource in text (§16.4, §16.6; D-MCP-13).
- *Tests:* §22.5's §16 row (2024-11-05 to 2026-07-28, small and over-limit results).
- *Final:* resolved.

**T3-11. The `record.proto` freeze had no versioning or hashed-bytes rule.** R3 runtime major. *Partly valid: owner decision 25 has DESIGN.md freeze it, and disclosure after erasure is impossible by design. Fix-modified.*
- *Changed:* frozen means wire-stable, and versions add fields (§16.8 "What freezes"; D-MCP-6):
  - RecordEntry, CanonicalAction, ApprovalRequest and ApprovalDecision carry versions;
  - every hash and signature covers stored bytes;
  - RECORD.md owns an open kind registry;
  - log order is (push version, position).
- *Declined:* moving the log matrix to RECORD.md.
- *Tests:* §22.6's vectors and fuzz; FS-25 to FS-29 at M3's exit.
- *Final:* resolved; the erasure-disclosure reason holds.

**T3-12. Mandatory read receipts had no authorized write path.** R1 S15; R1b S07. *Valid; fix.*
- *Changed:* non-writer readers of an owner-bound repo get a budgeted deposit scope of 4 KiB per deposit and 256 a day (§16.8, §7.8, §8.5, §11.12; D-MCP-18).
  - They deposit a sealed `read` entry before decrypting, and a first read that cannot deposit fails closed.
  - An EvsShare opens an owner-bound repo only with receipts, from M3.
- *Disclosed:* receipts are cooperative.
- *Tests:* FS-30.
- *Final:* resolved. New: RT-N7 (fixed).

**T3-13. An SDK transport rejection became identity revocation.** R1 S12; R1b S08; R2 F23. *Valid; fix (T2-38 merged).*
- *Changed:* the sdk consumes generation-bearing logout events (§18.7, §18.5, §5.6; D-SDK-14; D-CORE-8 changes to match).
  - A confirmed 401, a strict expiry or parent loss maps to Unenrolled with a reason, keeping identity and admission.
  - Revoked follows only a SidecarRevoke that verifies against the config.
  - Events of older generations are dropped.
- *Tests:* §22.5's §18 row.
- *Final:* resolved.

**T3-14. The keystore API could not say "locked".** R1 S13; R1b S09. *Valid; fix (T2-39 merged).*
- *Changed:* SidecarKeyStore returns gobind-safe statuses: Present, Absent, Locked and Failed (§18.5, §5.9; D-SDK-15, D-CORE-15).
  - Locked and Failed never create, overwrite or delete.
  - A root key is created only on Absent with no recorded `sidecar_id`.
- *Tests:* §22.5's §18 row.
- *Final:* resolved.

**T3-15. One local root key linked a person's networks.** R1 C02; R2 "Cross-network keychain separation". *Partly valid; fix (T2-30 merged).*
- *Changed:* an instance unlock key, wrapped by the OS keystore and the pass, opens per-network roots. Each root is also wrapped only to its own network's recovery key (§5.9; D-CORE-14; D-CORE-10 changes to match).
- *Tests:* §22.5's §5 row (one network's recovery code, with a copy of the whole state directory, opens no other network's keychain).
- *Final:* resolved.

**T3-16. Wake dispatch used a cross-slot transaction and could lose its trigger.** R1 S17; R1b S17; R2. *Valid; fix (T4-24 merged).*
- *Reviewers split:* R2 read an EXEC then a separate enqueue, R1b one MULTI. The text described one MULTI with a branch, so the fix specifies R2's sequence.
- *Changed:* §18.7 and §6.8 (WK1-WK4; D-SDK-16):
  - a slot-local hint script returns `tok` and `live`;
  - a separate XADD runs only for token holders, now or, while `live`, 15 s later;
  - delivery is recorded from connect's per-frame ack;
  - the mail router sends forced hints;
  - tokens are re-projected after a Redis loss.
- *Tests:* FS-36, on a 3-master cluster.
- *Final:* resolved; the obligation-record decline holds, and a sentinel per slot now re-projects the tokens of any lost master (RT-N5, fixed). New: RT-N4 (fixed).

**T3-17. HTTPS-only hosts had no liveness lease, and the long poll had no body.** R1 S16; R1b S18; R3 "§6 is not a wire spec" (poll body). *Valid; fix.*
- *Changed:*
  - Polls refresh a narrow `network_client_lease` row at most every 5 min.
  - An ephemeral client with no connection is reaped once its lease and its newest disconnect are both over 35 min old, so a connected agent survives a short blip.
  - An unload beacon closes it early by a 128-bit capability (§18.8, §7.7; D-SDK-17).
  - The poll answers 200 `PollResponse`, never 204, and a reset applies only once complete (§6.8; D-PROTO-5).
- *Tests:* FS-37.
- *Final:* resolved.

**T3-18. One browser origin was the decryption boundary.** R3 client major; CRITIC4 minors 6, 11. *Valid; fix, residual disclosed (T2-41 merged).*
- *Changed:* a key origin, `https://sidecar.ur.io`, holds the Worker, the key and the token. ur.io frames it under a strict CSP and `frame-ancestors`, and its exact-origin API returns views only. Its block states the admission flow (a consented device online) and the Workers' leaf cost (§18.8, §2.4 TB1, §2.8 EX7, §2.10; D-SDK-18).
- *Residual:* script running in a ur.io page reads views while it runs.
- *Tests:* §22.9's Browsers row (Playwright).
- *Final:* resolved. New: RT-N8 (fixed).

**T3-19. A missed wasm size goal had no defined browser path.** R3 client major. *Partly valid: ur.io already serves a gated ~75 MB build. Fix-modified.*
- *Changed:* the page Worker builds the root with `-tags sidecar_http` and links no connect or gVisor package (§18.10, §5.4, §4.6, §4.7; D-SDK-19).
  - §5.4's kept types use the root's own Id and Logger, with a net/http SidecarApi for bind, DPoP refresh and the exchange.
  - The gate is 40 MB, with 12-20 MB estimated.
  - C17 is needed only for the extension.
- *Tests:* `make check`'s `sidecar_http` leg from M1; `make size`.
- *Final:* resolved.

**T3-20. Where the device role's code lives (Q-SDK-5).** R3 and R3b Q-SDK-5; R1, R1b and R2 Q-SDK-5. *Valid; fix: (b) now.*
- *Reviewers split:* R1, R1b and R2 preferred (a) unless the size gate failed; R3 and R3b preferred (b).
- *Changed:* the role is `sidecar/device`, which imports only connect and a generated `sidecar/protocol/bridge`.
  - `protocol/bridge` imports only std and protobuf. It holds everything the role verifies: AuthPin, AuthEntry, the headers, Signed and the statements it applies (§4.4, §6.9, §7.9).
  - `make check` fails the ios_extension leg if it links the root or `protocol`.
  - The changes sit in §18.13, §17.10 and §2.10 (D-SDK-20).
- *Tests:* `make check`; `make size`'s 1 MiB gate at M4.
- *Final:* resolved.

**T3-21. P0 and tokens: what the server actually enforces.** R3 C3; R3b C3 disposition; the Q-CORE-4 answers of all five reviews; R2 F23. *Partly valid: strict_exp, the M1-M2 confinement and the stage order were already in place. Fix.*
- *Changed:* §7.4 and D-TRUST-3:
  - one verifier enforces strict expiry for routes, the exchange and connect's transport;
  - a fail-closed route allowlist for strict_exp bearers;
  - auth codes carry their `api_key_id`, closing AUTH.md:202;
  - until stage 2, enrollment is limited to `preview_networks`.
- Q-CORE-4 is closed as (b): a DPoP proof by the ClientKey on refresh, the exchange and auth-client, wired through `Api.SetDpopSigner` (§5.13, §7.8, §18.7).
- *Tests:* §22.5's §7 row (a copied token, a replayed proof, an older key, an ordinary refresh).
- *Final:* fixed: §7.4's stage 2 waits for the extension release that stops persisting `by_jwt`, which §23.7 schedules, and until then `ur` refuses to enroll beside either stored credential (§5.6; D-TRUST-3; section 6.1).

**T3-22. The module identity, the release rewrite and the nested-module layout.** R2 F15; R1 architecture note. *Partly valid; fix-modified.*
- *Reviewers split:* R1 was right that the release rewrite already handles `/v2026` (build/all/run.sh); R2 was right that the text never said so.
- *Changed:*
  - The development path stays unversioned, and §4.9 states the release rewrite.
  - `cli/`, `smtpproof/` and `mlsinterop/` are nested modules, and the root requires no module of this repository (owner decision 104) (§4.4, §4.7; D-REPO-1, D-REPO-2).
- *Tests:* §22.4's tagged-consumer release fixture.
- *Final:* resolved.

**T3-23. The sandbox operator was missing from the threat model.** R3 client major (T2-40 merged). *Valid; disclose, plus detection.*
- *Changed:*
  - A cloud agent's sandbox operator sits inside TB1, like the OS (§2.4, §2.6).
  - T3-21 bounds the exposure: no renewal, exchange or child without the ClientKey.
  - `ur status` reports TLS interception (§18.9, §16.9, §2.10).
- *Not adopted:* pinning platform hosts, which needs its own rotation process, when the operator already holds the VM's keys.
- *Tests:* the privacy harness's intercepting proxy (CC4).
- *Final:* disclosed; the pinning decline holds, but §2.18 does not repeat the residual.

**T3-24. Pre-approved auth keys mixed the server bearer with client-only secrets.** R1 F17; R1b C01. *Valid; fix (one design with T2-29).*
- *Changed:* as T2-29. In addition, the daemon keeps only the Delegation's reader key, and redaction refuses the bundle (§7.8, §5.6, §16.7; D-TEAM-5, D-TEAM-22).
- *Tests:* §22.7's auth-key cases.
- *Final:* resolved.

**T3-25. One-command admin tokens had no command binding.** R1 C02; R1b C11. *Valid; fix.*
- *Changed:* a `cmd` claim covers method, path and JCS body, with consent through RFC 9396 `authorization_details`. An `admin_token_use` row in the command's transaction makes a replay return the stored result (§7.8, §5.7, §2.8 api-11; D-TEAM-7).
- *Tests:* §22.5's §7 row.
- *Final:* resolved.

**T3-26. Shared-purpose Signed records could be reinterpreted across types.** R1 C02; R1b C11. *Valid; fix (one order with T2-10).*
- *Changed:* the type is bound into the signed bytes. §6.11's SignedType registry is numbered by owner service, and verifiers refuse an unexpected type (§6.9, §6.11; D-PROTO-7).
- *Tests:* §22.6's cross-type matrix.
- *Final:* resolved.

**T3-27. Browser verification came after the first browser release.** R1 S18. *Already fixed: §22.9 and §22.17 put the page Worker's tests at M4. Decline.* T3-18 adds the key-origin cases. *Final:* declined-as-stated.

### 3.4 Edges, mail and network (T4)

**T4-01. The SMTP proof did not authenticate the server state that interprets the bytes.** R1 F15; R1b F14; R3 C6; R3b DATA and BDAT major. *Partly valid: the relation was deferred to SPEC.md, so this was a missing obligation. Fix.*
- *Changed:* §14.5's relation proves the MX's authenticated replies (Z7-Z9) under private server keys (D-SMTP-22).
  - Parts name the server records they cover, and no message record passes the edge until they do.
  - BDAT's body streams unopened under a count bound, so a padded record may fail the send but smuggles nothing.
  - The sidecar pipelines only on PIPELINING, and the M9 gate names the TLS 1.3 client.
- *Tests:* FS-31; §22.10's M9 evidence.
- *Final:* resolved; the formal state machine waits for SPEC.md at M9. New: EM-N4 (fixed).

**T4-02. DATA mode could not finish a large message inside its 2 h limit.** R3b major; CRITIC4 minor 3. *Accepted residual (owner decision 125); disclose.*
- *Disclosed:* the cap is `smtp_data_proof_bytes`, measured per host: about 1 MiB on the M1 reference and 600 KiB on an m5.large. A larger message to an MX without CHUNKING gets a DSN before MAIL (§14.5; D-SMTP-20; §14.15). The receiver copy says large attachments may miss that minority until a faster prover (Later) (§15.9, §18.5).
- *Final:* disclosed. The copy gives no size, though a ~1 MiB cap catches ordinary photos, and it sits on `GetReceiverCoverage`, an inbound API, while the limit is outbound.

**T4-03. The X-UR-Ref medium join was not bound to the verified DKIM `d=`.** R3 C6. *Valid; fix.*
- *Changed:* a medium-confidence join counts only if a verifying DKIM signature's `d=` is the network the X-UR-Ref MAC encodes (§14.8; D-SMTP-8).
- *Tests:* §22.5's §14 row (the replay case).
- *Final:* resolved.

**T4-04. A custom-domain CNAME let the operator replace the effective CAA policy.** R1 F13; R1b F15; R2 F13. *Valid; fix.*
- *Changed:* strong mode keeps effective CAA under customer authority: customer A/AAAA or flattening, and no CNAME into the operator zone.
  - certs checks the whole discovery chain at setup and at renewal, and desktops check it before each order.
  - A strong-mode host whose walk reaches an operator name is refused.
  - A CNAME host is weak mode, disclosing EX1's operator-issuance exception (§12.8, §13.8, §12.14; D-DNS-9, D-TLS-11).
- *Tests:* FS-32.
- *Final:* resolved. New: EM-N3 (fixed).

**T4-05. Strict direct MX in the URnetwork zone still trusted operator-controlled discovery.** R1 F14; R1b F16. *Valid; fix-modified: the claim is narrowed, and the path stays with EX2's residual.*
- *Changed:* the "cannot redirect a DANE sender" claim holds only when the MX selection and its TLSA are both in customer-signed zones. Only that mail carries `tls_basis.strict_custom_mx`. A URnetwork-zone direct MX is ordinary mail (§15.4, §15.5, §12.8; D-MAIL-12).
- *Tests:* FS-33.
- *Final:* resolved; FS-33 lacks R1b's mixed arrangements, which the text covers.

**T4-06. The outer 443 split never sent custom-domain SNI to tlsedge.** R1 S07; R1b S12; R2 F20; R3 major. *Valid; fix.*
- *Changed:* the lb's SNI map includes a generated map of active custom hosts. It is regenerated with the port-80 names on every add and removal and reloaded at most once per 15 min, and unknown SNI keeps the platform default (§13.4, §12.8, §19.5 W1; D-TLS-12).
- *Tests:* FS-35.
- *Final:* resolved. The activation barrier is a fixed wait: nothing confirms each lb loaded the map, and probes test only `<root>` names.

**T4-07. Empty ALPN selected raw forwarding around the HTTP audience check.** R1 F12; R1b F17; R2 C02. *Valid; fix.*
- *Changed:* dispatch binds to the signed registration's AppMode, never to the visitor's ALPN.
  - An `http` registration sends no-ALPN connections through the HTTP front.
  - `raw` is allowed only under `public` or a `link` whose grant pins a client certificate (§13.7, §9.4-§9.5, §8.4, §13.9; D-TLS-13).
- *Tests:* FS-34.
- *Final:* resolved.

**T4-08. Report intake could not parse aggregate counts, and the soundness alarm compared the wrong units.** R1 S09; R1b S13; R2 F21. *Valid; fix.*
- *Changed:*
  - A bounded aggregate parser reads DMARC XML and TLS-RPT JSON: size, ratio, entity and depth limits, reporter checks and `report_id` dedup. Enclosed bodies stay undecoded.
  - The RUA anomaly compares proven per-recipient counts and is an investigation signal (§14.8, §14.14; D-SMTP-23).
- *Tests:* FS-39.
- *Final:* resolved.

**T4-09. Deferred mail authentication lost reception-time DNS evidence.** R1 S10; R1b S14. *Valid; fix.*
- *Changed:* the receiver seals a bounded MailAuthEvidence into the deposit, bound to the message hash, the time and itself. Ingest labels from it, never from later DNS (§15.5, §15.7; D-MAIL-14).
- *Tests:* FS-39; §22.7 S7.
- *Final:* resolved; no risk row says a compromised receiver can forge reception-time verdicts. New: EM-N1 (fixed).

**T4-10. REQUIRETLS and the operator list are inferences, not proof of prior privacy.** R1 C01; R1b S15; R3 "Q-MAIL-13 (b) is the wrong label"; R3b note. *Accepted residual (owner decision 135); disclose.*
- *Disclosed:* §15.5, §2.8 EX3 and §2.18 say the operator list is a reputation check, not proof of a DANE or MTA-STS path. REQUIRETLS records only the final hop's requirement. No UI or API claims end-to-end path confidentiality (D-MAIL-13).
- *Tests:* FS-39; §22.7's two-hop fixture.
- *Final:* disclosed; R1's separate observable-fact labels were not adopted (owner decision 135). New: EM-N2 (fixed).

**T4-11. The directive and the no-plaintext statement omitted the platform report listener.** R1 S11; R1b S16; R2 "Raw abuse-report privacy"; R3 major. *Valid; fix.*
- *Changed:* D-TRUST-4, I-2 and R-TEST-3 name the one exception, `rpt.bringyour.com`'s listener. It terminates TLS, parses headers and aggregate report data only, seals the raw bytes and persists no plaintext (§2.8 mx-4, §14.8, §15.4). smtp-2 lists `helo_name`.
- *Front matter:* the directive's inbound-mail bullet carries the same clause (FRONT-1).
- *Tests:* the privacy harness and the schema guard.
- *Final:* resolved: D-MAIL-1 and the sections' requirement rows name the listener, and since the 2026-11-05 close-out build so do the front matter's X6 row and Appendix A's D-MAIL-1 row.

**T4-12. A replying burner's first DKIM record deleted its MX.** R3 and R3b majors; CRITIC4 minor 2. *Valid; fix.*
- *Changed:* in the journal write that adds a burner's first `_domainkey` child, dns writes copies of the wildcard's MX and A/AAAA records at `<blabel>`. It removes them with the last selector, and health drops update every copy (§12.6, §12.7, §15.9; D-DNS-11).
- *Tests:* §22.7 S10; §22.5's §12 row.
- *Final:* resolved.

**T4-13. iOS in the foreground is not a receive path.** R3 and R3b majors. *Valid; disclose (owner decision 12 stands).*
- *Disclosed:* §15.6 says foreground iOS only resyncs, so iOS-only users may miss codes. `GetReceiverCoverage` returns `foreground-only` with that copy (§15.9, §18.5).
- *Gate:* M8's release readiness requires the receiver paths and the receiver prompt to pass, and requires the copy to show before a first burner. It is never a per-user gate (§23.4).
- *Final:* resolved. R3's retryable close for offline networks and cacheable failure for unknown names were not taken, and no reason is recorded for unknown SNI.

**T4-14. Owner decision 66 removed caps but left the sockets control plane unbounded.** R3 major. *Valid; fix.*
- *Changed:* a per-client token bucket over Finds and registration pages of at most 1,024 entries answers `unavailable` before any sampling or signing. Find's spend check answers `quota` before signing. No count of names, listeners or streams is capped (§9.10, §9.6; D-SOCK-15).
- *Tests:* §22.5's §9 row.
- *Final:* resolved; registration is not refused for a spent network, with the same outcome.

**T4-15. C13 did not say which id is sealed, or the signer and companion rules.** R3 major; R2 F01 (mechanics). *Valid; fix (with T2-26).*
- *Changed:* in every mode the signer fills the source subject from the source client's stored `acl_subject_client_id`, never a request field. It seals that subject with the source network, the class and the WindowDelegation. Companions inherit the seals, and only the dialer's network is escrowed (§6.10.1, §4.6 C13, §8.10, §17.9; D-PROTO-19).
- *Tests:* FS-38; §22.7's FriendsAndFamily assertions.
- *Final:* resolved.

**T4-16. The overlay /16 was both captured and dropped under a CGNAT overlap.** R3 major. *Valid; fix.*
- *Changed:* on overlap, the device routes peers by /32 and carves out every local /32 its physical path needs: interfaces, gateways and resolvers. It never drops the block, and it exports per-peer /32s while those are unknown (§17.4, §17.7; D-BRIDGE-12, D-BRIDGE-16).
- *Tests:* §22.9's CGNAT fixture.
- *Final:* resolved; the CGNAT fixture lacks a carrier resolver in the block.

**T4-17. Rule order exposed the provider's own daemon listeners on 127.0.0.1.** R3 major. *Partly valid: owner decision 120 keeps LAN allow-all without a document. Fix-modified.*
- *Changed:* a rule 0 ahead of every Pass denies flows to this device's own daemon listeners on any local address. Other LAN and loopback reach is unchanged (§17.6, §2.10; D-BRIDGE-19).
- *Tests:* §22.7 S8.
- *Final:* resolved.

**T4-18. §6 was not a wire spec.** R3 major. *Valid; fix (with T3-17).*
- *Changed:* codes are frozen enums, each but ErrorCode with 0 as UNSPECIFIED, which is a protocol error. §9's reject codes map one to one. The poll body is PollResponse, and a partial PushReset applies nothing (§6.5, §6.7, §6.8, §9.6; D-PROTO-20).
- *Tests:* §22.5's §6 row; §22.6.
- *Final:* fixed: §6.5-§6.7 define StreamClose.final_offset, the window values and a response's Envelope.type, and §9.4 K's HKDF labels and the listing seal's nonce and additional data, all freezing with §6 at M2 (section 6.1).

**T4-19. Shared sending IPs had no drain target.** R3 major. *Partly valid; accepted residual (owner decision 124); disclose.*
- *Disclosed:* a listed address leaves the sending set within the feed refresh, and mail moves to the other shared addresses. FCrDNS precedes any send. Enough listings degrade sending and shared ingress together, as accepted (§14.6, §14.9, §14.15, §21.5, §21.17).
- *Final:* disclosed.

**T4-20. Bridge pins expired before the flows they protect.** R2 F22. *Valid; fix.*
- *Changed:* pins key on the source-destination pair and exist only where a choice of link exists (§17.5, §17.8; D-BRIDGE-7).
  - An edit moves no pinned pair off a link that still serves it.
  - A removed link drains for max(`drain_seconds`, 600 s) for TCP.
  - A full table leaves new pairs unpinned and refuses nothing (owner decision 66).
- *Tests:* §22.7's pin cases; §22.9's mobile churn.
- *Final:* resolved; a full pin table leaves new pairs unpinned (owner decision 66), disclosed and counted.

**T4-21. Bridge-share aliases needed a capacity preflight.** R1b C09; R2 "Share prefix representation". *Valid; fix.*
- *Changed:* `accept-invite` runs a preflight. Aliases live in the upper /17, and hosts in the lower /17. A target wider than /17 is refused as too large, and one with no free aligned block as no space. The refusal reaches the inviter (§17.4, §17.9, §17.16; D-BRIDGE-20).
- *Tests:* §22.7's share cases.
- *Final:* resolved.

**T4-22. §19.7's MG7 omitted `mail_direct_mx`.** R3 known gap 1. *Already fixed; decline.* *Final:* not re-checked.

**T4-23. DNS and DANE run at a single site (owner decision 123).** R3 major; R3 Q-DNS-7. *Accepted residual; disclose.*
- *Disclosed:* §12.12, §12.15, §15.16 and §2.18 now agree. A site outage stops every `<root>` name, DNS-01, DANE and, from M7, inbound mail. It pages at all hours (owner decision 143), and an outage longer than a sender's retry window, 14 h to 5 days, bounces that sender's mail.
- *Final:* disclosed, but §23.4's M7 row and §23's risks do not carry it, as R3 asked.

**T4-24. Wake dispatch used a cross-slot MULTI and a stale live marker.** R1b S17. *Merged into T3-16.* Its pending-wake obligation record was not adopted. Wakes are best effort (owner decision 88), and finding an obligation after a crash would need a cross-slot scan. *Final:* resolved, as T3-16.

**T4-25. Revocation did not fence a flow whose dial was in progress.** R2 "Flow revocation versus dial completion". *Valid; fix.*
- *Changed:* a flow registers its rule and policy generation before dialing. A revocation swaps the policy, then CloseFlows cancels older-generation flows, dials included. A completing dial rechecks before its first byte (§17.6, §17.8, §4.6 C5; D-BRIDGE-21).
- *Tests:* FS-56.
- *Final:* resolved.

**T4-26. The edge ticket exception could be read to waive source identity.** R1b C08; R2 "Socket ticket source binding". *Valid; fix.*
- *Changed:* source equality always holds. Only the Hello check is waived for edges, and an edge ticket names only a `tls/` or `smtp/` name (§9.6; D-SOCK-12).
- *Tests:* §22.5's §9 row.
- *Final:* resolved.

**T4-27. TLS 1.2 server-key disclosure.** R1 F16; R3 C6; R3b's C6 disposition. *Already fixed in mechanism: Z1 proves the server Finished in-circuit, and no key that opens application data is disclosed (D-SMTP-21). Fix, test only.*
- *Tests:* FS-31. An honest 451 against a forged 250: the sender keeps and retries the message, and the edge reads no MX reply.
- *Final:* resolved. New: EM-N4 (fixed).

**T4-28. Burner domains do not inherit network MTA-STS.** R1 S08; R2 C05. *Already fixed: §15.5 says burners rely on DANE. Disclose the residual.*
- *Disclosed:* for burner mail, a listed operator's MTA-STS enforcement does not apply (§15.5, §15.11, §15.16).
- *Tests:* §22.7 (no MTA-STS claim for burner mail).
- *Final:* resolved. New: EM-N2 (fixed).

### 3.5 Ops, tests and phasing (T5)

**T5-01. The durability sentence and table overstated what holds.** R3 C7; R3b finding 5, before-M2 5; CRITIC4 Major 6, minor 1. *Valid; fix.*
- *Changed:* §19.6's table:
  - RPO 0 for a drive, a host, and a second host for protected objects, inside owner decision 89's targets, which cover drives and hosts only;
  - past half a set or at the site, every object no device holds is lost, with no RTO target (owner decision 94);
  - the Postgres rows take the dump RPOs of T5-03.
- D-OPS-14 and R-OPS-9 change to match.
- *Final:* fixed: the table gives RPO 0 by object state (SL-N4, fixed), and §19.10 keeps rows newer than the main dump, so the Postgres rows' ≤ 24 h holds (OT-N1, re-checked resolved; section 6.1).

**T5-02. Surviving two hosts needs a protected-object condition.** R1b S11; R1 S05. *Valid; fix.*
- *Changed:* reads survive two hosts only for objects with every shard (§19.6, §19.8, §19.10, §19.17).
  - Each set reports protected, degraded or at_risk; at_risk pages.
  - Every return of a drive or host starts a full heal.
  - M3's drill measures heal throughput.
- *Not adopted:* all-drive acknowledgment, which turns one host's outage into a write outage.
- *Tests:* FS-40.
- *Final:* fixed: D-OPS-14's paragraph and table now follow the parity bullet's per-object rule (SL-N4; section 6.1).

**T5-03. The Postgres-held state had no specified dump, and the runbook restored the wrong one.** R3 C7; R3b finding 5, before-M2 5; CRITIC4 Major 6, Q6. *Valid; fix.*
- *Changed:* D-OPS-18 is a daily dump of the durable sidecar tables, read from the primary in its nightly slot and kept off site, 14 generations at each place.
  - RPO is at most 24 h plus the run at the primary, and 26 h at the site, while each nightly run completes. A skipped run adds a day and warns (§19.6, §19.14).
  - It starts at MG0's Gn-out (M0) and is restore-drilled before M3's pilot (§19.11, §19.18, §23.4).
- *Tests:* FS-42; the restore drill.
- *Final:* fixed: the dump carries the parent rows and the restore follows the newer dump, so ≤ 24 h and ≤ 26 h hold (OT-N1, re-checked resolved), and Q-OPS-3's residual is marked closed (OT-N7; section 6.1). New: OT-N6 (fixed).

**T5-04. A dump-age restore reopened alias takeover and lost identities, revocations and holds.** R3 C7; R3b finding 5; CRITIC4 Major 6. *Valid; fix.*
- *Changed:* §19.10's Postgres-loss and site-loss recovery:
  - CT replay re-binds labels certified since the dump (§12.8), so I-14 holds;
  - `restore_required` makes daemons re-register (§5);
  - the authorization log resumes from devices' verbatim entries (§7.9);
  - revocations are rebuilt;
  - meters re-send idempotently;
  - holds are re-placed and counsel told;
  - re-seed mode mints only re-seed tokens (§7.8).
- *Tests:* FS-41, FS-42.
- *Final:* resolved: OT-N1 and OT-N2 re-checked resolved, §12.6's restore step reconciling the zone before api's replay. Minor leftovers remain in §7.10's wording, FS-42, FI-12 and §12.6's unmapped owners (section 6.2).

**T5-05. Re-seeding had no key-closure contract for mirrors.** R1b F11; R1 F18; R2 C03; R3 C7; R3 GC major. *Valid; fix (with T1-14).*
- *Changed:* erasure statements re-seed first, and covered keys and segments are refused. Re-seeds are taken only for repos the access log shows live or restorable, via RepoDelete and RepoRestore (§8.8), and EvsReseed covers heads below a pin (§19.10, §11.13, §11.6, §6.9).
- *Disclosed (§2.18):* an offline mirror keeps its key until it syncs.
- *Tests:* FS-41.
- *Final:* resolved; "covered ... segments", which nothing defined, is dropped (SL-N5, fixed).

**T5-06. Who re-forms owner-bound groups after a site loss was unnamed.** CHECK4 minor 10. *Valid; fix (with T2-35).*
- *Changed:* repo admins' devices re-form groups, and for owner-bound repos only the owner's consented device does (§19.10, §10.8; D-KEYS-13).
- *Tests:* FS-41.
- *Final:* not re-checked.

**T5-07. Staffed-hours operations did not meet the 4 h RTO and 99.9% SLOs.** CRITIC4 Major 7, Q7; R3 C7 and its Q-ABUSE-6 row; R1b priorities (which disagreed). *Partly valid; owner item, decided by owner decision 143.*
- *Reviewers split:* R1b read owner decisions 95 and 134 as general staffing. We read them as abuse-review decisions, and owner decision 116 bought the cold spare "so a second host failure still meets the 4 h RTO".
- *Changed:* a two-person out-of-hours rota from M3, with 30-minute acknowledgment, for the page classes. Registrar and law-enforcement notices join it at M5 (R-OPS-11, §19.6, §19.8, D-OPS-9, §19.11, §19.17, §12.6, §12.15, §23.7).
- *Tests:* FS-50.
- *Final:* resolved; R1b's staffing reading is declined as stated. New: OT-N6 and OT-N9 (fixed).

**T5-08. Daily Stripe metering had no uncertainty policy.** R2 C04 (first half). *Valid; fix.*
- *Changed:* §20.9 Meters (D-QUOTA-8):
  - transfer and storage overage are pre-aggregated daily, so a re-send replaces;
  - periods anchor at 00:00 UTC;
  - invoices get 72 h of grace;
  - rows are versioned;
  - uncertain sends retry with the same identifier inside Stripe's windows, and none reads a summary;
  - a row that misses finalization is never billed later.
- *Tests:* FS-43.
- *Final:* resolved.

**T5-09. Usage producers lost or double-counted their 60-second windows.** R2 C04 (second half). *Valid; fix.*
- *Changed:* `ReportUsage` takes a UsageBatch keyed by `batch_id`, applied once in api's transaction and kept 24 h. Producers flush on SIGTERM. An unclean exit loses at most one window, and a batch unanswered for 10 min is dropped and alerted (§20.6, §20.7, §20.14, §2.8 api-13).
- *Tests:* FS-44.
- *Final:* resolved.

**T5-10. Relayed same-network bytes were debited only at close.** R3 major. *Partly valid: R3's 45 GiB per-contract figure is wrong, since grants cap at 256 MiB. Fix-modified: reserve at creation instead of R3's checkpointed debits.*
- *Changed:* CreateContract for a relayed pair first reserves its grant through the Redis reservations that escrow uses. The grant is sized to the balance, and settlement debits once per contract and returns the rest (§20.6, §20.10, §20.15; D-QUOTA-4).
- *Tests:* FS-45.
- *Final:* resolved; the reservation holds.

**T5-11. A downgrade withheld custom domains, breaking inbound addresses.** R3 operations major. *Valid; fix.*
- *Changed:* after 14 days, web hosts and the From address are withheld, while mail hosts keep MX, TLSA and routing (§20.7).
- *Tests:* FS-51.
- *Final:* resolved.

**T5-12. Quota limits could block safety maintenance.** R1b C05; R1 C02. *Valid; fix (with T1-16).*
- *Changed:* §20.7, §20.5 and §11.13 let maintenance pushes pass at the limit and while spent.
- *Tests:* FS-47.
- *Final:* fixed (owner decision 146; rounds 5-6), as T1-16.

**T5-13. The storage quota was reconciled from a log that carries no sizes.** R3 GC-and-quotas major; R1b S03. *Valid; fix (with T1-15).*
- *Changed:* stored bytes are the LIST sizes of `seg/`, `pack/` and `hp/` plus batch-resident lengths, less hold-only objects. They are counted nightly, and usage batches move the count between passes (§20.7; D-QUOTA-3).
- *Tests:* FS-60, FS-47.
- *Final:* resolved. New: OT-N5 (fixed).

**T5-14. The credit line's draw order had no correctness design (Q-QUOTA-3's residual).** R3 and R3b answers; R2 priorities. *Valid; fix.*
- *Changed:* one comparator, `escrowDrawLess`, with `team_credit` last, orders every draw site, and every return runs in reverse.
  - Invariants E-a to E-e hold, and the 5% benchmark stays.
  - Both gate M6's entry (§20.9, §20.12, §22.10, §23.6, §23.8; D-QUOTA-9).
- *Tests:* FS-46, gated at M6's entry.
- *Final:* resolved. New: OT-N3 (fixed).

**T5-15. Abuse clocks did not match business-hours staff.** R3 major and its Q-ABUSE-6 row; R1b priorities. *Partly valid: business-hours clocks are owner decision 134's choice, and are disclosed. Fix-modified inside that decision.*
- *Changed:* §21.8 and §21.9:
  - every registrar or registry notice about `<root>` pages both rota members, at any hour, from M5;
  - phishing, malware and C2 reports get 4 business hours on every tier;
  - production orders go to counsel's out-of-hours contact.
- D-ABUSE-3 changes to match.
- *Tests:* FS-49.
- *Final:* resolved.

**T5-16. §21.9 understated what legal process can produce, and holds did not survive the site.** R3 major, C7 and its Q-EVS-7 row. *Partly valid; fix.*
- *Changed:* §21.9 lists the producible rows with their retention, including the 300-day contract pairs, the edge records and gkm's membership ids. It states that a site loss voids what a hold kept on the file cluster.
- *Final:* resolved.

**T5-17. One generic 90+90-day hold could not carry §2258A's one-year preservation.** R2 "Legal-hold kind". *Valid; fix, with counsel to confirm.*
- *Changed:* holds gain a kind with per-kind deadlines (§21.9, §21.16, §2.8 api-14, §23.7; D-ABUSE-6):
  - preserve_2703f: 90 days plus one renewal;
  - report_2258a: one year.
- Overlapping holds keep a scope until the latest deadline. `copied_rows` also copies in-scope Redis soft state.
- *Tests:* FS-48.
- *Final:* resolved.

**T5-18. The test program had no deterministic fault-schedule harness or shared invariants.** R1's and R1b's priorities, assertions and invariants; R2 priorities; R1b F06; every "deterministic acceptance" paragraph. *Valid; fix.*
- *Changed:* D-TEST-10:
  - a `sidecartest/fault` harness: named barriers, FaultPlan results such as ApplyThenDrop, QuorumLoss and DriveMiss, a fake clock and restartable actors;
  - no sleeps, and a positive twin for every refusal;
  - real handlers in T3;
  - a seeded explorer;
  - `EvsCommit.tla` over separate objects;
  - Porcupine;
  - FI-1 to FI-14;
  - FS-1 to FS-63, each with owner, invariants, tier and gate (§22.8, §22.4, §22.15, §22.17).
- *Final:* resolved. New: OT-N5 and OT-N9 (fixed).

**T5-19. Release migrations were not exercised against the previous binary.** R1b priorities. *Partly valid; fix.*
- *Changed:* FS-55 applies N+1 while N runs, restarts N on the new schema, then enables N+1, at every Gn-out.
- *Final:* resolved.

**T5-20. The protobuf fuzz oracle demanded byte-identical re-marshalling.** R2 "Protobuf fuzz oracle". *Valid; fix.*
- *Changed:* the oracle compares with `proto.Equal` after unmarshal and compares re-encoding with deterministic marshal. It seeds non-canonical forms and verifies signatures over the received bytes (§22.6; D-TEST-4).
- *Final:* not re-checked.

**T5-21. S2 and the twenty-agent test assumed disjoint pushes land on shared refs.** CRITIC4 Major 1. *Valid; fix.*
- *Changed:* S2 follows §11.7's modes. On a shared git-mode ref the second push gets a non-fast-forward and its merge lands. No acknowledged commit is lost, and oids match a second device's (§22.7 S2, §22.8, §11.14).
- *Tests:* FS-5.
- *Final:* resolved.

**T5-22. Format freezes at M2's entry claimed evidence that exists only at its exit.** R2 priorities; R3 internal-gates major and before-G0 item 8; R3b before-M2 7; R1 and R1b priorities. *Valid; fix.*
- *Changed:* D-PHASE-7 freezes each format twice.
  - **Specification, at Gn-in:** peer review, TLC, the FS rows written, vector schemas and RECORD.md.
  - **Bytes, at Gn-out:** the FS rows passing on their tiers, Porcupine, the 0x0010 interop, the benchmark and the sizes.
- Production holds no format before its final freeze (§22.10, §23.4, §23.8, §11.21; D-TEST-9).
- *Final:* resolved. New: OT-N3 (fixed).

**T5-23. Suite 0x0010 froze on vectors run under 0x0001, with no hybrid interop.** R3b ladder major, before-M2 7; R3 internal-gates major. *Valid; fix (with T2-25).*
- *Changed:* §22.10's 0x0010 interop artifact, required for the suite's final freeze at M2's exit (D-KEYS-10).
- *Final:* resolved. New: WR-N8 (fixed).

**T5-24. The M9 proof gate had no independent relation checker and no per-check mutation.** R3 internal-gates major; R1b F14; R1 priorities. *Valid; fix of the gate.*
- *Changed:* §22.10's M9 evidence adds:
  - a relation checker written outside the prover tree;
  - one mutated witness per E1-E3 and Z1-Z9 check that only that check refuses;
  - FS-31's scripted MXs.
- *Final:* resolved.

**T5-25. M2 bundled every freeze under one exit with no stated critical path.** CRITIC4 Q10. *Partly valid; fix.*
- *Changed:* the MLS subset and its KAT start at M0. §23.5 states the critical path, owner decision 43's 2-4 engineer-months and then the interop, with other M2 work against a fake GKM. §23.15 adds the slip risk (D-PHASE-4).
- *Final:* not re-checked.

**T5-26. One `sidecar` branch let a Gn-out land another track's unfinished migrations.** R3 major, known gaps and Q-OPS-8 row. *Partly valid: owner decision 118 had already removed the RS1 fork. Fix.*
- *Changed:* a migration group stays pending under the build tag `sidecar_pending` until its own Gn-out (§19.7, §23.9, §4.8; D-OPS-6).
  - Release legs never set the tag.
  - The pending file panics outside local, T3 and canary.
- *Tests:* FS-54.
- *Final:* resolved.

**T5-27. The 443 split first met production traffic at its rollout.** R3 internal-gates major. *Partly valid; fix.*
- *Changed:* each interface first runs the split drained from DNS answers, reached only by probes and §13.4's bench, then rejoins (§19.5 W1, §13.4).
- *Final:* resolved.

**T5-28. Small repos' push logs never packed.** CHECK4 minor 7. *Valid; fix, superseded by owner decision 136.* As T1-21: §19.9's `hp/` row; FS-53. *Final:* resolved, as T1-21.

**T5-29. No measurement before year two showed the HDD drive-operation ceiling.** CRITIC4 Q9; R1 and R1b Q-OPS-2 notes. *Valid; fix.*
- *Changed:* §22.8's `hdd` row runs year two's small-object mix on the production segment cluster before it holds data (M3). Q-OPS-2's switch keys on its result.
- *Final:* resolved. New: OT-N4 (fixed).

**T5-30. G0's ceiling rule failed 21 sections on a missing sentence.** R3 known gap 5; CRITIC4 minor 10. *Partly valid: no section was more than 10% over. Fix, then superseded.*
- *Changed:* §23.8's G0 no longer applies OUTLINE's word ceilings (+10%). Since 2026-11-04 it applies a density rule instead: no content duplicated across sections (each item in its owning section, cited elsewhere), normative formats and state machines in fenced blocks, and dense prose. The assembler renders Appendix G as a link to §2.8.
- *Why:* the normative formats and state machines peer review required put every section over its ceiling (the assembly's word table), and a ceiling would cut normative content where the rule cuts repetition.
- *Final:* not re-checked.

**T5-31. Q-TEST-6's stated reason was false.** R3 and R3b. *Valid; fix.*
- *Changed:* Q-TEST-6 is closed as (b), with the real reason: per-field oneof allocations on hot paths (§22.13, §6.11).
- *Final:* resolved.

**T5-32. R3's claim that owner decision 20's text lacks the 500-800 PUT/s ceiling.** R3 Q-OPS-2 major. *Invalid; decline.* The decision reads "the cluster caps at roughly 500–800 small PUT/s". *Final:* declined-as-stated.

**T5-33. Items already fixed in the 2026-11-04 draft.** R3 known gaps 1-4 and its Q-OPS-1 row; R2's Q-CTX-4 and browser points; R1b's source-graph point. *Already fixed; decline.*
- §19.7's MG7 lists `mail_direct_mx`.
- §23.6's M2 row lists Q-CTX-4.
- No stray X tags remain.
- D-CTX-2 states that section tables gain no R-CTX column.
- §19.9 sizes `epoch/`.
- The browser tests are at M4.
- The lock pins `urfoundation/sn`.
- *Final:* resolved.

**T5-34. Tier-varying endpoint caps were not named as derived limits.** CRITIC4 minor 4. *Already fixed (§20.4, D-QUOTA-7); decline.* *Final:* not re-checked.

**T5-35. The 1,001st member device and the rotation-rate inputs were unstated.** CRITIC4 minors 7, 11. *Partly valid; fix-modified, superseded by owner decision 144.*
- *Changed:* §20.4 has no member-device cap. §19.9's `gen/` row counts only reaps no Delegation covers, as an upper bound until M2 measures it.
- *Final:* not re-checked; its §20.4 half is owner decision 144's, which the panel found resolved.

### 3.6 The storage tier and the IOPS fit (owner decisions 136-140, 145)

These are not review findings. The owner fixed the hardware during the response (owner decisions 136-139) and required the design to fit it (owner decision 140). The T6 redesign that followed replaced the T1 mechanisms noted in T1-03, T1-04, T1-10, T1-18, T1-19 and T1-21. Format 1's signed bytes did not change: batches, places, window entries, receipts, folds and parcels are server-internal, and the read API returns the same statements.

- **Hardware (§19.6; R-OPS-12; D-OPS-19).** 8 × PM9A3 1.92 TB, 2 per host, EC:4 (~7.7 TB usable), with 2-4 PM9A3 spares, `mkfs.xfs -i maxpct=25`, 4 KiB or 1 KiB blocks (decided by §22.8), 512 B LBA kept, and drive counters and SMART wear exported.
- **Writes (§11.8, §11.7, §11.13).**
  - ~9 KiB heads of 64-byte window entries (D-EVS-29);
  - minute-bucketed batch records, written at once under light load and within 20 ms under load (D-EVS-30);
  - lazy folds of committed versions (D-EVS-31);
  - hourly evacuation into packs and parcels, with pack-before-index-before-delete and container-keyed `pidx/` entries (D-EVS-32; I-EVS-7);
  - receipts instead of upload markers (D-EVS-34);
  - leases, the push sequence and gkm acks in Redis, beside the verified head and projection caches (`{evsh_}` §11.9, `{acl_}e` §7.9; D-EVS-14, D-KEYS-21).
- **Budget (§11.13; R-EVS-19; D-EVS-33).** Each metadata cluster has one write budget, measured from drive counters and refilled at 0.768 DWPD.
  - P0 work (revocation, `proj/`, shred, erasure) is never refused.
  - P1 pushes are priced at admission with the folds and evacuation they cause.
  - P2 background work spends what P1 leaves and keeps a floor above its ~37% steady share (40% until measured).
  - The heaviest network per weight is refused first.
- **Growth (§11.8 Placement; §19.9; owner decision 145).** A create-only `place/<repo_id>` on the first cluster places each new repo and its gkm group. The next cluster is ordered at owner decision 136's triggers or their projection over the lead time, at about 1.25× year one. Pools are refused by FS-63.
- **Fit, by the model.** These are inferences until §22.8 measures them.
  - Year one: ~43 KiB a push per drive (~33 on 1 KiB blocks), 0.40 DWPD (0.31), ~3% of rated write IOPS, and reads at ~0.3% of 800k.
  - Per set: ~400-450 pushes/s (~530-600 on 1 KiB blocks). Batches are per evs process and cluster, so a set near capacity sees ~1-1.6 records a batch (§11.13); at the model's high constants a set carries ~310-330 (§11.20).
  - Year two: five to six clusters.
- **Q-EVS-9, closed.** Owner decision 140's record first gave ~10-15 KiB a push, a design-team estimate below the head overwrite's ~14 KiB floor. The corrected record makes the drive budget the target (section 6.3).
- **Tests.** FS-57 to FS-63; FI-14; §22.8's `nvme`, `fold`, `trash` and `hdd` rows; the D-TEST-11 gate.
- *Final (storage-tier cluster):* 28 of 30 checks resolved, among them the hardware, packing, soft state, small heads, batches, receipts, the write governor, the XFS and MinIO settings, the gate, growth by clusters and the per-set capacity, which reproduces from the model. Partial: D-EVS-31's lazy folds, and R3b finding 1 through them (ST-N1), since fixed (owner decision 148; rounds 5-6): removal folds write versioned tombstone markers with If-Match, never blind deletes. New: ST-N2 to ST-N5 (fixed) and ST-N6 (already fixed in the owner's record).

## 4. Index by review

Every finding that the design team's finding index (peer/INDEX.md) lists for R1, R1b, R2, R3 and R3b appears once in its review's table: 264 rows in all.

- **Columns.** "Entry" is the consolidated entry in section 3, or the peer-review question that closed the item. "Where" gives each entry's main place in the revised text; rows that touch three or more entries give one place per entry.
- **Final.** The second-round panel's status for the finding, as the final rounds changed it (section 1). Where the panel checked it under another name, or checked only its entries or its question, the cell says "as …", "by entry" or "by question". Where two clusters disagree, the weaker status stands.
- **Dispositions.** They are the registers' own. Owner items are shown as decided.
- **Differences from INDEX.md.** In a few rows INDEX.md abbreviates the disposition:
  - it lists T4-02, T4-10, T4-13 and T4-19 as fixes, where the registers have disclosures that also changed text;
  - it lists T4-05 and T4-17 as fixes, where the registers have fix-modified;
  - it lists T4-27, T4-28 and T5-15 as already fixed, where the registers have, respectively, a test-only fix, a disclosure and a fix-modified.

  This file follows the registers.

### 4.1 R1 (DESIGN-REVIEW1.md; Astra, 2026-11-03 draft): 42 items

| Finding | Entry | Disposition | Where | Final |
|---|---|---|---|---|
| F01 Authorization state needs both a delta-prefix commitment … | T2-01 | fix | §7.9 log; §10.6; D-TEAM-19 | resolved |
| F02 v0 witnesses do not exchange ordinary evs ref heads | T1-11, T2-07 | all fix | §6.4-§6.5 RefHead; §11.8; §6.5; D-PROTO-17 | resolved |
| F03 Mutually stale witnesses cannot establish the claimed … | T2-05 | disclose | §2.8 exposure bound; §6.17 | disclosed |
| F04 All-devices-lost recovery has both a bootstrap gap and a … | T2-08, T2-09 | all fix | §7.9 recovery window; D-TEAM-21; §10.8; §10.9 | resolved |
| F05 Ephemeral-device restrictions conflict with the effective … | T2-13 | fix | §8.4-§8.6; D-ACL-19 | fixed (6.1) |
| F06 Rotating a compromised recovery code does not retire every … | T1-22, T2-12 | all fix | §11.6 due; §11.7; §7.9; §10.8; §11.6 | fixed (6.1) |
| F07 The proposed Git bridge cannot preserve Git semantics under … | T1-05 | fix; Q-EVS-8 decided (owner decision 141) | §11.7 modes; §11.11; D-EVS-22, -28 | resolved |
| F08 Ambiguous head-commit outcomes must never enter ordinary … | T1-02 | fix | §11.8 Outcomes; D-EVS-23 | resolved |
| F09 The revocation gate and the ref commit point are separate … | T1-06 | fix | §11.8 Gate; §10.6; D-EVS-18 | resolved |
| F10 Path-epoch cutover lacks a complete snapshot and overlap … | T1-07 | fix | §11.6 path epochs; D-EVS-12 | resolved |
| F11 Restore races irreversible slot deletion | T1-12 | fix | §11.12 Deletion; §8.8; D-EVS-19 | resolved |
| F12 ALPN absence selects a raw path without a defined audience … | T4-07 | fix | §13.7; §9.4-§9.5; D-TLS-13 | resolved |
| F13 The prescribed CNAME defeats the claimed customer CAA … | T4-04 | fix | §12.8; §13.8; D-DNS-9, D-TLS-11 | resolved |
| F14 Strict direct MX still relies on operator-controlled … | T4-05 | fix-modified | §15.4; D-MAIL-12 | resolved |
| F15 The outbound proof does not establish that BDAT bytes will … | T4-01 | fix | §14.5 Z7-Z9; D-SMTP-22 | resolved |
| F16 Disclosing the TLS 1.2 server record key permits forged … | T4-27 | fix (test only; already fixed) | FS-31; D-SMTP-21 | resolved |
| F17 Pre-approved auth-key bundles need an explicit client-only … | T2-29, T3-24 | all fix | §7.8; D-TEAM-22; D-TEAM-5, -22 | resolved |
| F18 Mirrored recovery and cluster-only slot custody are … | T1-14, T5-05 | all fix | §11.13 Durability; §19.10; D-EVS-17; §11.13 | resolved |
| F19 Whole-tree scans cannot attribute changes safely enough for … | T3-07 | fix | §16.7; D-MCP-15 | fixed (6.1) |
| F20 Single-use approvals have no durable atomic consumption … | T3-01, T3-02 | all fix | §16.6 Consumption; §8.10; D-MCP-11; §16.6, §16.8; §8.8; D-MCP-12 | resolved |
| S01 Four index versions are not tied to committed visibility | T1-03 | fix | §11.7 index entries; D-EVS-31 | resolved |
| S02 Repo-wide hint topics use counters that are only monotonic … | T1-23, T2-22 | T1-23 decline (already fixed); T2-22 fix | §11.10; §6.8; §10.6; D-KEYS-19 | resolved (by entry) |
| S03 Committed-log-only GC cannot find never-committed uploads … | T1-04 | fix-modified | §11.13 GC, Uploads; D-EVS-25, -34 | resolved |
| S04 A lifetime ref-name key leaks guesses about branches … | T1-09 | disclose | §11.5; §2.8 evs-2 | disclosed |
| S05 Two-host read availability needs a fully protected-object … | T5-02 | fix | §19.6 protection states | resolved |
| S06 Deposit-only principals cannot fetch their required drop key | T2-20 | fix | §10.6; §10.14; D-KEYS-17 | resolved |
| S07 The 443 split sends custom-domain SNI to the platform … | T4-06 | fix | §13.4; §19.5 W1; D-TLS-12 | resolved |
| S08 Parent MTA-STS does not cover burner recipient domains | T4-28 | disclose (already fixed) | §15.5 | resolved |
| S09 The report parser excludes the formats carrying its … | T4-08 | fix | §14.8; D-SMTP-23 | resolved |
| S10 Deferred mail authentication loses reception-time DNS … | T4-09 | fix | §15.5, §15.7; D-MAIL-14 | resolved |
| S11 The absolute no-content-plaintext statement omits report … | T4-11 | fix | §2.8 D-TRUST-4, mx-4; I-2 | resolved |
| S12 A transport-token rejection is mapped to durable identity … | T3-13 (with T2-38) | fix | §18.7; §5.6; D-SDK-14 | resolved |
| S13 The keystore API cannot represent its required … | T3-14 (with T2-39) | fix | §18.5; §5.9; D-SDK-15, D-CORE-15 | resolved |
| S14 The advertised approval channels are unusable in supported … | T3-03 | fix | §16.6; D-SDK-9; D-MCP-14 | resolved |
| S15 Mandatory author-visible read receipts have no authorized … | T3-12 | fix | §16.8; D-MCP-18 | resolved |
| S16 HTTPS-only ephemeral hosts have no specified liveness lease | T3-17 | fix | §18.8; §6.8; D-SDK-17 | resolved |
| S17 A stale live marker suppresses the only wake trigger | T3-16 | fix | §18.7; §6.8; D-SDK-16 | resolved |
| S18 Browser verification is scheduled after the first public … | T3-27 | decline (already fixed) | §22.9 | declined-as-stated |
| C01 Q-MAIL-13 cannot make observed sender metadata a proof of … | T4-10 | disclose | §15.5; §2.8 EX3; D-MAIL-13 | disclosed |
| C02 Command consent, signature typing and local key isolation … | T1-16, T1-19, T2-10, T3-15 (with T2-30), T2-31, T3-25, T3-26, T5-12 | all fix | §11.13 limit; §11.13 negative; §6.9; §5.9; §10.4; §7.8; §6.9, §6.11; §20.7 | resolved |
| C03 Native presence approval needs a concrete platform evidence … | T3-06 | fix | §16.6 profiles; D-MCP-19 | resolved |
| C04 Persist run taint and bridge bootstrap authority across … | T2-27, T3-08 | all fix | §17.8; §18.6; D-BRIDGE-18; §16.6; D-MCP-16 | resolved |

### 4.2 R1b (DESIGN-REVIEW1b.md; Astra, 2026-11-04 draft): 54 items

| Finding | Entry | Disposition | Where | Final |
|---|---|---|---|---|
| F01 Effective authorization needs a delta-prefix commitment and … | T2-01 | fix | §7.9 log; §10.6; D-TEAM-19 | resolved |
| F02 Standalone wrapped-reader rotations are not ordered or … | T2-01, T2-02 | all fix | §7.9 log; §10.6; D-TEAM-19; §10.5-§10.6 gen/ claim; D-KEYS-15 | resolved |
| F03 Ephemeral deposit-only policy conflicts with ordinary … | T2-05, T2-13 | T2-05 disclose; T2-13 fix | §2.8 exposure bound; §6.17; §8.4-§8.6; D-ACL-19 | fixed (6.1) |
| F04 The chosen 72-hour recovery veto lacks its signed protocol | T2-08, T2-09 | all fix | §7.9 recovery window; D-TEAM-21; §10.8; §10.9 | resolved |
| F05 v0 witnesses do not compare ordinary evs ref heads | T1-11, T2-07 | all fix | §6.4-§6.5 RefHead; §11.8; §6.5; D-PROTO-17 | resolved |
| F06 Ambiguous head-CAS outcomes enter cleanup that can delete … | T1-02, T5-18 | all fix | §11.8 Outcomes; D-EVS-23; §22.8; D-TEST-10 | resolved |
| F07 The revocation gate is not fenced against a ref commit or … | T1-06 | fix | §11.8 Gate; §10.6; D-EVS-18 | resolved |
| F08 Path-key migration has no complete snapshot, stale-writer … | T1-07 | fix | §11.6 path epochs; D-EVS-12 | fixed (6.1) |
| F09 Path-level disjoint retries and pre-receive publication do … | T1-05 | fix; Q-EVS-8 decided (owner decision 141) | §11.7 modes; §11.11; D-EVS-22, -28 | resolved |
| F10 Restore can win after irreversible slot deletion has begun | T1-12 | fix | §11.12 Deletion; §8.8; D-EVS-19 | resolved |
| F11 Full mirrored recovery and cluster-only slot custody have … | T1-14, T5-05 | all fix | §11.13 Durability; §19.10; D-EVS-17; §11.13 | resolved |
| F12 Single-use approvals lack durable atomic consumption before … | T3-01, T3-02 | all fix | §16.6 Consumption; §8.10; D-MCP-11; §16.6, §16.8; §8.8; D-MCP-12 | resolved |
| F13 Whole-worktree snapshots cannot safely attribute changes to … | T3-07 | fix | §16.7; D-MCP-15 | fixed (6.1) |
| F14 The SMTP proof authenticates client bytes but not the … | T4-01, T5-24 | all fix | §14.5 Z7-Z9; D-SMTP-22; §22.10 | resolved |
| F15 Custom-domain CNAMEs permit the operator to replace the … | T4-04 | fix | §12.8; §13.8; D-DNS-9, D-TLS-11 | resolved |
| F16 Strict direct MX still trusts operator-controlled mail … | T4-05 | fix-modified | §15.4; D-MAIL-12 | resolved |
| F17 Empty ALPN selects raw forwarding without a defined … | T4-07 | fix | §13.7; §9.4-§9.5; D-TLS-13 | resolved |
| S01 Recovery-code replacement leaves the compromised path key … | T1-22, T2-12 | all fix | §11.6 due; §11.7; §7.9; §10.8; §11.6 | resolved |
| S02 Four index versions can all be pending and evict the … | T1-03 | fix | §11.7 index entries; D-EVS-31 | resolved |
| S03 Log-only GC cannot find uploads that never reached the log | T1-04, T1-15, T5-13 | T1-04 fix-modified; T1-15 fix; T5-13 fix | §11.13 GC, Uploads; §11.13 Quotas; §20.7 | resolved |
| S04 The maximum directory cardinality cannot fit the maximum … | T1-17 | fix | §11.7 directory | resolved |
| S05 Same-epoch GKM work hints are discarded by the generic … | T2-22 | fix | §6.8; §10.6; D-KEYS-19 | resolved |
| S06 Deposit permission does not consistently authorize fetching … | T2-20 | fix | §10.6; §10.14; D-KEYS-17 | resolved |
| S07 Mandatory author-visible read receipts lack an authorized … | T3-12 | fix | §16.8; D-MCP-18 | resolved |
| S08 An SDK transport-token rejection is mapped to durable … | T3-13 (with T2-38) | fix | §18.7; §5.6; D-SDK-14 | resolved |
| S09 The keystore API cannot express its required unavailable … | T3-14 (with T2-39) | fix | §18.5; §5.9; D-SDK-15, D-CORE-15 | resolved |
| S10 Ineligible devices can disable the only available approval … | T2-28, T3-03, T3-04 | all fix | §7.9; §16.6; §7.9 read_only | resolved |
| S11 Two-host read survival needs a fully protected-object … | T5-02 | fix | §19.6 protection states | fixed (6.1) |
| S12 The outer 443 split never sends custom-domain SNI to tlsedge | T4-06 | fix | §13.4; §19.5 W1; D-TLS-12 | resolved |
| S13 Header-only report parsing cannot produce the promised … | T4-08 | fix | §14.8; D-SMTP-23 | resolved |
| S14 Deferred mail authentication loses reception-time DNS … | T4-09 | fix | §15.5, §15.7; D-MAIL-14 | resolved |
| S15 REQUIRETLS is an observed requirement, not exact proof of … | T4-10 | disclose | §15.5; §2.8 EX3; D-MAIL-13 | resolved |
| S16 The global no-content-plaintext promise omits platform … | T4-11 | fix | §2.8 D-TRUST-4, mx-4; I-2 | resolved |
| S17 Wake dispatch has both a Redis Cluster transaction error … | T3-16 (with T4-24) | fix | §18.7; §6.8; D-SDK-16 | resolved |
| S18 HTTPS-only ephemeral hosts still have no authoritative … | T3-17 | fix | §18.8; §6.8; D-SDK-17 | resolved |
| C01 Separate redeemable enrollment credentials from client-only … | T2-29, T3-24 | all fix | §7.8; D-TEAM-22; D-TEAM-5, -22 | resolved |
| C02 Freeze the exact approver signature on GrantActivate | T2-10, T3-02 | all fix | §6.9; §7.9; §8.8; D-TEAM-20, -21; §16.6, §16.8; D-MCP-12 | resolved |
| C03 Presence approval needs a concrete platform evidence profile | T3-06 | fix | §16.6 profiles; D-MCP-19 | resolved |
| C04 Small-group GroupInfo publication still needs crash … | T2-21 | fix | §10.6; D-KEYS-18 | fixed (6.1) |
| C05 Preserve bounded safety maintenance at quota limits | T1-16, T5-12 | all fix | §11.13 limit; §20.7; §11.13 | fixed (owner decision 146; rounds 5-6) |
| C06 Distinguish retained proof records from retained inline … | T1-13 | fix | §11.12 Erasure; D-EVS-26 | resolved |
| C07 Subscription lease creation and its invalidation counter … | T1-18 | fix | §11.10 leases; D-EVS-14 | resolved |
| C08 The edge ticket exception must not waive source identity or … | T4-26 | fix | §9.6; D-SOCK-12 | resolved |
| C09 Bridge-share aliases need capacity preflight | T4-21 | fix | §17.9; D-BRIDGE-20 | resolved |
| C10 Persist security state across MCP and keyless-device … | T2-27, T3-08 | all fix | §17.8; §18.6; D-BRIDGE-18; §16.6; D-MCP-16 | resolved |
| C11 Close the remaining small wire and lookup ambiguities at … | T1-19, T2-10, T3-25, T3-26 | all fix | §11.13 negative; §6.9; §7.8; §6.9, §6.11 | resolved |
| Invariant 1: A committed head always has a complete, verifiable … | T1-01, T5-18 | T1-01 fix-modified; T5-18 fix | §11.8 write rules, I-EVS-1..7; D-EVS-13; §22.8; D-TEST-10 | resolved |
| Invariant 2: Each uncertain operation retains enough identity and state … | T1-02, T5-18 | all fix | §11.8 Outcomes; D-EVS-23; §22.8; D-TEST-10 | resolved |
| Invariant 3: Every head transition proves the relevant … | T1-06, T5-18 | all fix | §11.8 Gate; §10.6; D-EVS-18; §22.8; D-TEST-10 | resolved |
| Invariant 4: A generation has exactly one authenticated parent and … | T2-02, T5-18 | all fix | §10.5-§10.6 gen/ claim; D-KEYS-15; §22.8; D-TEST-10 | resolved |
| Invariant 5: A successful restore has all required keys; a winning shred … | T1-12, T5-18 | all fix | §11.12 Deletion; §8.8; D-EVS-19; §22.8; D-TEST-10 | resolved |
| Invariant 6: Pending state cannot evict the only committed readable … | T1-03, T1-04, T5-18 | T1-03 fix; T1-04 fix-modified; T5-18 fix | §11.7 index entries; §11.13 GC, Uploads; §22.8 | resolved |
| Invariant 7: Approval use is reserved before effect and remains consumed … | T3-01, T3-08, T5-18 | all fix | §16.6 Consumption; §16.6; §22.8 | resolved |
| Invariant 8: A restore action changes only attributable run-owned state … | T3-07, T5-18 | all fix | §16.7; D-MCP-15; §22.8; D-TEST-10 | resolved |

### 4.3 R2 (DESIGN-REVIEW2.md; Sol, 2026-11-03 draft): 51 items

| Finding | Entry | Disposition | Where | Final |
|---|---|---|---|---|
| F01 Authenticate native IP principals independently of the … | T2-26, T4-15 | all fix | §17.6, §17.9; §4.6 C13; D-BRIDGE-17; §6.10.1; D-PROTO-19 | resolved |
| F02 Unknown policy state must not select legacy allow-all | T2-27, T3-08 | all fix | §17.8; §18.6; D-BRIDGE-18; §16.6; D-MCP-16 | resolved |
| F03 Commit to the complete effective authorization state | T2-01 | fix | §7.9 log; §10.6; D-TEAM-19 | resolved |
| F04 Make drop-key freshness verifiable by a non-reader | T2-01, T2-19 | all fix | §7.9 log; §10.6; D-TEAM-19; §10.5; §11.12; D-KEYS-17 | resolved |
| F05 Arbitrary matching peers do not enforce the 24-hour removal … | T2-05 | disclose | §2.8 exposure bound; §6.17 | disclosed |
| F06 Specify recovery and deposit-only key-retrieval … | T2-08, T2-20 | all fix | §7.9 recovery window; D-TEAM-21; §10.6; §10.14; D-KEYS-17 | resolved |
| F07 Unknown CAS outcomes cannot trigger destructive cleanup | T1-02 | fix | §11.8 Outcomes; D-EVS-23 | resolved |
| F08 Choose Git ref semantics compatible with the committed tree | T1-05 | fix; Q-EVS-8 decided (owner decision 141) | §11.7 modes; §11.11; D-EVS-22, -28 | resolved |
| F09 Fence and compose path-epoch migrations | T1-07 | fix | §11.6 path epochs; D-EVS-12 | resolved |
| F10 Serialize segment publication with orphan collection | T1-04 | fix-modified | §11.13 GC, Uploads; D-EVS-25, -34 | resolved |
| F11 Erasure must cover every representation of a message | T1-13 | fix | §11.12 Erasure; D-EVS-26 | resolved |
| F12 Claim a terminal shred state before destroying keys | T1-12 | fix | §11.12 Deletion; §8.8; D-EVS-19 | resolved |
| F13 Keep effective custom-domain CAA under customer authority | T4-04 | fix | §12.8; §13.8; D-DNS-9, D-TLS-11 | resolved |
| F14 Run restore needs ownership, not just a before/after diff | T3-07 | fix | §16.7; D-MCP-15 | fixed (6.1) |
| F15 Align the module path with the calendar major version | T3-22 | fix-modified | §4.4, §4.7, §4.9; D-REPO-1, -2 | resolved |
| F16 Retain the current ordering frontier when pruning epochs | T2-23 | fix | §10.6 retention; D-KEYS-20 | resolved |
| F17 Scope notification cursors to the same entity as their … | T1-23 | decline (already fixed) | §11.10 | resolved |
| F18 Narrow or repair the post-removal ref-name leakage claim | T1-09 | disclose | §11.5; §2.8 evs-2 | disclosed |
| F19 Define a commit fence for repo gates and deletion | T1-06 | fix | §11.8 Gate; §10.6; D-EVS-18 | resolved |
| F20 Route custom SNI names to their sidecars | T4-06 | fix | §13.4; §19.5 W1; D-TLS-12 | resolved |
| F21 Normalize DMARC anomaly evidence to message evaluations | T4-08 | fix | §14.8; D-SMTP-23 | resolved |
| F22 Keep flow ownership for the complete promised drain | T4-20 | fix | §17.5; D-BRIDGE-7 | resolved |
| F23 Separate transport credential loss from authority revocation | T3-13 (with T2-38), T3-21 | all fix | §18.7; §5.6; D-SDK-14; §7.4; §5.13; D-TRUST-3 | resolved |
| F24 Render MCP results for the negotiated protocol | T3-10 | fix | §16.4, §16.6; D-MCP-13 | resolved |
| C01 Does “read-only browser” limit authority or only the UI? | T2-28, T3-04 | all fix | §7.9; §18.8; D-TEAM-24; §7.9 read_only | resolved |
| C02 Non-public raw TCP has no audience protocol | T4-07 | fix | §13.7; §9.4-§9.5; D-TLS-13 | resolved |
| C03 Define key coverage of a recoverable mirror | T1-14, T5-05 | all fix | §11.13 Durability; §19.10; D-EVS-17; §11.13 | resolved |
| C04 Daily metering needs an uncertainty policy, not an … | T1-15, T5-08, T5-09 | all fix | §11.13 Quotas; §20.9 Meters; §20.6-§20.7 | resolved |
| C05 Burner subdomains do not inherit network MTA-STS | T4-28 | disclose (already fixed) | §15.5 | resolved |
| Other contract: Cross-network keychain separation | T3-15 (with T2-30) | fix | §5.9; D-CORE-14 | resolved (by entry) |
| Other contract: Socket ticket source binding | T4-26 | fix | §9.6; D-SOCK-12 | resolved |
| Other contract: Flow revocation versus dial completion | T4-25 | fix | §17.6 C5; D-BRIDGE-21 | resolved |
| Other contract: Share prefix representation | T4-21 | fix | §17.9; D-BRIDGE-20 | resolved |
| Other contract: Legal-hold kind | T5-17 | fix | §21.9; D-ABUSE-6 | resolved (by entry) |
| Other contract: Raw abuse-report privacy | T4-11 | fix | §2.8 D-TRUST-4, mx-4; I-2 | resolved (as R1 S11) |
| Other contract: Sticky run taint | T3-08 | fix | §16.6; §18.6; D-MCP-16 | resolved (by entry) |
| Other contract: Protobuf fuzz oracle | T5-20 | fix | §22.6; D-TEST-4 | not re-checked |
| Recommendation: Q-CORE-4 | T3-21, Q-CORE-4 | T3-21 fix; Q-CORE-4 closed by peer review | §7.4; §5.13; D-TRUST-3 | resolved |
| Recommendation: Q-TEST-1 | Q-TEST-1 | closed by peer review | §22.13 | resolved |
| Recommendation: Q-TEST-2 | Q-TEST-2 | closed by peer review | §22.13; §22.4 | resolved |
| Recommendation: Q-TEST-6 | T5-31, Q-TEST-6 | T5-31 fix; Q-TEST-6 closed by peer review | §22.13; §6.11 | resolved |
| Recommendation: Q-KEYS-11 | T2-23, Q-KEYS-11 | T2-23 fix; Q-KEYS-11 closed by peer review | §10.6 retention; D-KEYS-20; §10.12 | resolved |
| Recommendation: Q-EVS-6 | T1-10, Q-EVS-6 | T1-10 fix-modified; Q-EVS-6 closed by peer review | §11.8 head; §11.9; D-EVS-24, -29; §11.17 | resolved |
| Recommendation: Q-OPS-2 | T1-20, Q-OPS-2 | T1-20 fix; Q-OPS-2 closed by peer review | §11.6; §11.13; D-EVS-27; §19.14 | resolved |
| Recommendation: Q-BRIDGE-2 / Q-SDK-5 | T3-20, Q-BRIDGE-2, Q-SDK-5 | T3-20 fix; Q-BRIDGE-2 closed by peer review; Q-SDK-5 closed by peer review | §18.13; §17.14 | resolved; Q-SDK-5 declined-as-stated |
| Recommendation: Q-OPS-5 | Q-OPS-5 | closed by peer review | §19.14 | resolved |
| Recommendation: Q-CTX-4 | T5-33, Q-CTX-4 | T5-33 decline (already fixed); Q-CTX-4 closed by peer review | §1.13; §9 D-SOCK-16; §23.6 M2 row | fixed (6.1) |
| Recommendation: Q-KEYS-13 | none (the liveness point is T2-37's) | no change: owner decision 113 decided it | §10.9; §3.13 | resolved |
| Recommendation: Q-ACL-9 | T2-03, T2-04 | T2-03 fix; T2-04 disclose | §10.5 KeyHolders; D-KEYS-16; §2.9 I-15; §10.5 | disclosed |
| Recommendation: Q-TEAM-10 / Q-TEAM-11 | T2-08, T2-18 | all fix | §7.9 recovery window; D-TEAM-21; §7.9 cascade; D-TEAM-26 | resolved |
| Recommendation: Q-MAIL-13 | T4-10 | disclose | §15.5; §2.8 EX3; D-MAIL-13 | disclosed |

### 4.4 R3 (DESIGN-REVIEW3.md; 2026-11-03 draft): 80 items

| Finding | Entry | Disposition | Where | Final |
|---|---|---|---|---|
| C1 A ref commit does not publish the entry versions it names | T1-01, T1-02 | T1-01 fix-modified; T1-02 fix | §11.8 write rules, I-EVS-1..7; D-EVS-13; §11.8 Outcomes; D-EVS-23 | resolved |
| C2 Path-level success and a git ref are two histories | T1-05, T1-24 | T1-05 fix; Q-EVS-8 decided (owner decision 141); T1-24 decline (already fixed) | §11.7 modes; §11.11; D-EVS-22, -28; §11.8 parts; D-EVS-20 | resolved |
| C3 The P0 does not close before the daemon, and a 7-day `exp` … | T3-21 | fix | §7.4; §5.13; D-TRUST-3 | fixed (6.1) |
| C4 Harness evidence is a signature by the sidecar that was … | T3-05 | owner item, decided (owner decision 142) | §16.6; D-MCP-9; §16.12 Q-MCP-6 | disclosed |
| C5 A withheld removal is not bounded by 24 hours | T2-05, T2-06, T2-34 | T2-05 disclose; T2-06 fix-modified; T2-34 disclose | §2.8 exposure bound; §6.4-§6.6; §7.6 | fixed (owner decision 147; rounds 5-6) |
| C6 The outbound proof is a sketch, and TLS 1.2 shows … | T4-01, T4-03, T4-27 | T4-01 fix; T4-03 fix; T4-27 fix (test only; already fixed) | §14.5 Z7-Z9; §14.8; FS-31 | resolved |
| C7 Site loss does not restore the rows names and mail live on … | T5-01, T5-03, T5-04, T5-05, T5-07, T5-16 | T5-01 fix; T5-03 fix; T5-04 fix; T5-05 fix; T5-07 owner item, decided (owner decision 143); T5-16 fix | §19.6; §19.10 recovery; §19.10; §19.8; §21.9 | resolved |
| Major: The content-key ladder is not MLS forward secrecy or post-compromise … | T2-24 | fix-modified | §10.5; D-KEYS-1; R-KEYS-12 | resolved |
| Major: Harvest-now-decrypt-later is passive-only, and the ladder makes a … | T2-24, T2-25 | T2-24 fix-modified; T2-25 fix | §10.5; D-KEYS-1; R-KEYS-12; §10.4; §22.10; D-KEYS-10 | fixed (6.1) |
| Major: Q-ACL-9 (a) breaks removal. | T2-03, T2-04 | T2-03 fix; T2-04 disclose | §10.5 KeyHolders; D-KEYS-16; §2.9 I-15; §10.5 | disclosed |
| Major: The authority grammar already crowns one recovery key. | T2-08 | fix | §7.9 recovery window; D-TEAM-21 | resolved |
| Major: The id-only projection is not the policy the client evaluates. | T2-14 | fix | §8.4-§8.6, §8.11-§8.12; D-ACL-20, -21 | resolved |
| Major: Every admitted sidecar reads the directory and `K_sock`. | T2-15 | disclose | §2.6; §7.9 | disclosed |
| Major: JIT links a pre-registered email. | T2-16 | fix | §7.6; D-TEAM-23 | resolved |
| Major: Q-TEAM-10 (a) | T2-18 | fix | §7.9 cascade; D-TEAM-26 | fixed (owner decision 149; rounds 5-6) |
| Major: §6 is not a wire spec. | T3-17, T4-18 | all fix | §18.8; §6.8; D-SDK-17; §6.5, §6.7-§6.8; D-PROTO-20 | fixed (6.1) |
| Major: C13 does not say which id is sealed. | T2-26, T4-15 | all fix | §17.6, §17.9; §4.6 C13; D-BRIDGE-17; §6.10.1; D-PROTO-19 | resolved |
| Major: Decision 66 removes caps and does not bound the control plane. | T4-14 | fix | §9.6, §9.10; D-SOCK-15 | resolved |
| Major: The overlay /16 both captures CGNAT and is dropped because of it. | T4-16 | fix | §17.4, §17.7; D-BRIDGE-12 | resolved |
| Major: M4 ships allow-all to LAN and loopback for untagged sidecar sources. | T4-17 | fix-modified | §17.6 rule 0; D-BRIDGE-19 | resolved |
| Major: Q-BRIDGE-2. | Q-BRIDGE-2 | closed by peer review | §17.14 | resolved |
| Major: Q-CTX-4. | T5-33, Q-CTX-4 | T5-33 decline (already fixed); Q-CTX-4 closed by peer review | §1.13; §9 D-SOCK-16; §23.6 M2 row | resolved |
| Major: Foreground iOS is not a receive path. | T4-13 | disclose | §15.6, §15.9; §23.4 M8 | resolved |
| Major: A Team custom name on 443 is terminated. | T4-06 | fix | §13.4; §19.5 W1; D-TLS-12 | resolved |
| Major: The first DKIM record on a burner deletes its MX. | T4-12 | fix | §12.7; D-DNS-11 | resolved |
| Major: Shared sending IPs have no drain. | T4-19 | disclose | §14.6; §21.5 | disclosed |
| Major: M7 does not wait on a second site for DNS. | T4-23 | disclose | §12.15; §2.18 | disclosed |
| Major: Q-MAIL-13 (b) is the wrong label. | T4-10 | disclose | §15.5; §2.8 EX3; D-MAIL-13 | disclosed |
| Major: The platform listener is a real exception the directive sentence … | T4-11 | fix | §2.8 D-TRUST-4, mx-4; I-2; X6 row; D-MAIL-1 | resolved (close-out build) |
| Major: Relayed same-network bytes are debited at close. | T5-10, T5-11 | T5-10 fix-modified; T5-11 fix | §20.6; D-QUOTA-4; §20.7 | resolved |
| Major: M5's abuse clocks do not match the staff. | T5-15 | fix-modified | §21.8; D-ABUSE-3 | resolved |
| Major: §21.9 understates what a warrant returns. | T5-16 | fix | §21.9 | resolved |
| Major: M3 and M5 have no deployment path that satisfies both the migration … | T5-26 | fix | §19.7; D-OPS-6 | resolved |
| Major: The internal gates do not exercise the suite or the proof that ship. | T2-25, T5-22, T5-23, T5-24, T5-27 | all fix | §10.4; §22.10; §19.5 W1 | resolved |
| Major: Head readers cannot bind the file they were served. | T1-10, T1-23 | T1-10 fix-modified; T1-23 decline (already fixed) | §11.8 head; §11.9; D-EVS-24, -29; §11.10 | disclosed |
| Major: GC and quotas cannot see the bytes they account. | T1-04, T1-13, T1-15, T5-13, T5-05 | T1-04 fix-modified; T1-13 fix; T1-15 fix; T5-13 fix; T5-05 fix | §11.13 GC, Uploads; §11.12 Erasure; §11.13 Quotas; §20.7; §19.10 | resolved |
| Major: Path tokens work for a client that already knows the path, and the … | T1-07, T1-08 | all fix | §11.6 path epochs; D-EVS-12; §11.6 Tokens; §2.8 evs-2 | resolved (as SL-N2, re-checked) |
| Major: Q-OPS-2 should not freeze the locator. | T1-20, T5-32, Q-OPS-2 | T1-20 fix; T5-32 decline (invalid); Q-OPS-2 closed by peer review | §11.6; §19.6; §19.14 | resolved |
| Major: `record.proto` is not a semantics-free envelope. | T3-11 | fix-modified | §16.8; D-MCP-6 | resolved |
| Major: The tool catalog does not close the trusted action. | T3-09 | fix | §16.5-§16.6, §16.8; D-MCP-17 | resolved |
| Major: One browser sidecar is the plaintext boundary, and the label does not … | T3-18 | fix | §18.8 key origin; D-SDK-18 | resolved |
| Major: A failed size spike has no browser path that meets X14. | T3-19 | fix-modified | §18.10; §5.4; D-SDK-19 | resolved |
| Major: Q-SDK-5. | T3-20, Q-SDK-5 | T3-20 fix; Q-SDK-5 closed by peer review | §18.13; §4.4; D-SDK-20 | resolved |
| Major: The sandbox operator is not in the threat model. | T3-23 (with T2-40) | disclose | §2.4 TB1; §2.10; §18.9 | disclosed |
| Answer: Q-CORE-4 | T3-21, Q-CORE-4 | T3-21 fix; Q-CORE-4 closed by peer review | §7.4; §5.13; D-TRUST-3 | resolved (by question) |
| Answer: Q-EVS-6 | T1-10, Q-EVS-6 | T1-10 fix-modified; Q-EVS-6 closed by peer review | §11.8 head; §11.9; D-EVS-24, -29; §11.17 | disclosed (as the head-readers major) |
| Answer: Q-OPS-2 | T1-20, Q-OPS-2 | T1-20 fix; Q-OPS-2 closed by peer review | §11.6; §11.13; D-EVS-27; §19.14 | resolved (as the Q-OPS-2 major) |
| Answer: Q-KEYS-11 | T2-23, Q-KEYS-11 | T2-23 fix; Q-KEYS-11 closed by peer review | §10.6 retention; D-KEYS-20; §10.12 | resolved (by question) |
| Answer: Q-TEST-1 | Q-TEST-1 | closed by peer review | §22.13 | declined-as-stated (by question) |
| Answer: Q-TEST-2 | Q-TEST-2 | closed by peer review | §22.13; §22.4 | resolved (by question) |
| Answer: Q-TEST-6 | T5-31, Q-TEST-6 | T5-31 fix; Q-TEST-6 closed by peer review | §22.13; §6.11 | resolved (by question) |
| Answer: Q-BRIDGE-2 | Q-BRIDGE-2 | closed by peer review | §17.14 | resolved |
| Answer: Q-CTX-4 | T5-33, Q-CTX-4 | T5-33 decline (already fixed); Q-CTX-4 closed by peer review | §1.13; §9 D-SOCK-16; §23.6 M2 row | resolved |
| Answer: Q-SDK-5 | T3-20, Q-SDK-5 | T3-20 fix; Q-SDK-5 closed by peer review | §18.13; §4.4; D-SDK-20 | resolved (by question) |
| Answer: Q-OPS-5 | Q-OPS-5 | closed by peer review | §19.14 | resolved (by question) |
| Answer: Q-QUOTA-3 | T5-14, Q-QUOTA-3 | T5-14 fix; Q-QUOTA-3 closed by peer review | §20.9; D-QUOTA-9; §20.12 | resolved (by question) |
| Owner-question row: Q-TRUST-7 | T4-17, T2-27 | T4-17 fix-modified; T2-27 fix | §17.6 rule 0; D-BRIDGE-19; §17.8; §18.6; D-BRIDGE-18 | resolved (by entry) |
| Owner-question row: Q-TRUST-8 | T2-24 | fix-modified | §10.5; D-KEYS-1; R-KEYS-12 | fixed (as the HNDL major) |
| Owner-question row: Q-TEAM-10 | T2-08, T2-18 | all fix | §7.9 recovery window; D-TEAM-21; §7.9 cascade; D-TEAM-26 | fixed (owner decision 149; rounds 5-6; as the Q-TEAM-10 major) |
| Owner-question row: Q-TEAM-11 | T2-08 | fix | §7.9 recovery window; D-TEAM-21 | resolved (by entry) |
| Owner-question row: Q-ACL-9 | T2-03, T2-04 | T2-03 fix; T2-04 disclose | §10.5 KeyHolders; D-KEYS-16; §2.9 I-15; §10.5 | disclosed (as the Q-ACL-9 major) |
| Owner-question row: Q-KEYS-13 | T2-03 | fix | §10.5 KeyHolders; D-KEYS-16 | resolved (by entry) |
| Owner-question row: Q-KEYS-12 | T2-36 | fix | §10.12 Q-KEYS-12; gkm-6 | not re-checked |
| Owner-question row: Q-DNS-7 | T4-23 | disclose | §12.15; §2.18 | disclosed (as the M7 DNS major) |
| Owner-question row: Q-SMTP-6 | T4-19 | disclose | §14.6; §21.5 | disclosed (as the sending-IP major) |
| Owner-question row: Q-MAIL-13 | T4-10 | disclose | §15.5; §2.8 EX3; D-MAIL-13 | disclosed (as the Q-MAIL-13 major) |
| Owner-question row: Q-SMTP-1 | T4-01, T4-02 | T4-01 fix; T4-02 disclose | §14.5 Z7-Z9; D-SMTP-22; §14.5 DATA mode; D-SMTP-20 | disclosed (by entry) |
| Owner-question row: Q-TLS-8 | none | no change: owner decision 121 | §13.4 | not re-checked |
| Owner-question row: Q-ABUSE-6 | T5-07, T5-15 | T5-07 owner item, decided (owner decision 143); T5-15 fix-modified | §19.8; D-OPS-9; §19.14 Q-OPS-9; §21.8; D-ABUSE-3 | resolved (by entry) |
| Owner-question row: Q-EVS-7 | T5-16 | fix | §21.9 | resolved (by entry) |
| Owner-question row: Q-OPS-1 | T5-33 | decline (already fixed) | §19.14 Q-OPS-1; §19.9 | not re-checked |
| Owner-question row: Q-OPS-8 | T5-26 | fix | §19.7; D-OPS-6 | resolved (as the migrations major) |
| Owner-question row: Q-BRIDGE-5 | none | no change: owner decision 130 | D-TRUST-8; Appendix A | not re-checked |
| Owner-question row: Q-PHASE-7 | T3-21 | fix | §7.4; §5.13; D-TRUST-3 | fixed (as C3) |
| Known gap 1: §19.7's MG7 lists `mail_network` and `mail_host_key` and … | T4-22, T5-33 | all decline (already fixed) | §19.7 MG7 | not re-checked |
| Known gap 2: §23.6 omits Q-CTX-4. That is worse than the gap list says … | T5-33, Q-CTX-4 | T5-33 decline (already fixed); Q-CTX-4 closed by peer review | §1.13; §9 D-SOCK-16; §23.6 M2 row | resolved (as the Q-CTX-4 answer) |
| Known gap 3: Q-SOCK-3 and Q-ABUSE-1 still open with an X tag that … | T5-33 | decline (already fixed) | §9.13 Q-SOCK-3; §21.14 Q-ABUSE-1 | not re-checked |
| Known gap 4: D-CTX-2's R-CTX column was not added. Appendix F traces by … | T5-33 | decline (already fixed) | §1.12 D-CTX-2 | not re-checked |
| Known gap 5: The word-ceiling overages were not recomputed. G0 still … | T5-30 | fix | §23.8 G0 | not re-checked (superseded by the density rule) |
| Worse gaps: Worse gaps the list does not mention: the migration tail versus a … | T5-26, T5-01 | fix; fix; the HE request and the Appendix A tags need no change (owner decisions 124, 112, 130) | §19.7; §19.6; §19.11 | resolved (by entry) |

### 4.5 R3b (DESIGN-REVIEW3b.md; 2026-11-04 draft): 37 items

| Finding | Entry | Disposition | Where | Final |
|---|---|---|---|---|
| Finding 1 The head commit still does not publish the entry bytes it … | T1-01, T1-02, T1-05 | T1-01 fix-modified; T1-02 fix; T1-05 fix; Q-EVS-8 decided (owner decision 141) | §11.8 write rules, I-EVS-1..7; §11.8 Outcomes; §11.7 modes | fixed (owner decision 148; rounds 5-6) |
| Finding 2 The 72-hour exposure bound does not survive the server the … | T2-05, T2-06 | T2-05 disclose; T2-06 fix-modified | §2.8 exposure bound; §6.17; §6.4-§6.6; §8.10; D-PROTO-17, -18 | fixed (owner decision 147; rounds 5-6) |
| Finding 3 Harness evidence is still a hook any same-uid process can … | T3-05 | owner item, decided (owner decision 142) | §16.6; D-MCP-9; §16.12 Q-MCP-6 | disclosed |
| Finding 4 A removed wrapped writer can still sample the next … | T2-03, T2-04 | T2-03 fix; T2-04 disclose | §10.5 KeyHolders; D-KEYS-16; §2.9 I-15; §10.5 | resolved |
| Finding 5 Site loss still restores the wrong Postgres, and the RPO … | T5-01, T5-03, T5-04, T5-05 | all fix | §19.6; §19.10 recovery; §19.10 | resolved |
| Major: The content-key ladder is not the post-compromise security D-KEYS-1 … | T2-24, T2-25, T5-23 | T2-24 fix-modified; T2-25 fix; T5-23 fix | §10.5; §10.4; §22.10 | resolved |
| Major: A head reader still cannot bind the file it was served. | T1-10, T1-23 | T1-10 fix-modified; T1-23 decline (already fixed) | §11.8 head; §11.9; D-EVS-24, -29; §11.10 | disclosed |
| Major: DATA mode cannot finish a large message inside its own limit, and the … | T4-02, T4-01 | T4-02 disclose; T4-01 fix | §14.5 DATA mode; D-SMTP-20; §14.5 Z7-Z9; D-SMTP-22 | disclosed |
| Major: A replying burner's DKIM name still deletes its MX. | T4-12 | fix | §12.7; D-DNS-11 | resolved |
| Major: iOS in the foreground is still not a receive path. | T4-13 | disclose | §15.6, §15.9; §23.4 M8 | resolved |
| Answer: Q-EVS-6 | T1-10, Q-EVS-6 | T1-10 fix-modified; Q-EVS-6 closed by peer review | §11.8 head; §11.9; D-EVS-24, -29; §11.17 | disclosed |
| Answer: Q-OPS-2 | T1-20, Q-OPS-2 | T1-20 fix; Q-OPS-2 closed by peer review | §11.6; §11.13; D-EVS-27; §19.14 | resolved |
| Answer: Q-CORE-4 | T3-21, Q-CORE-4 | T3-21 fix; Q-CORE-4 closed by peer review | §7.4; §5.13; D-TRUST-3 | resolved |
| Answer: Q-TEST-1 | Q-TEST-1 | closed by peer review | §22.13 | declined-as-stated |
| Answer: Q-TEST-2 | Q-TEST-2 | closed by peer review | §22.13; §22.4 | resolved |
| Answer: Q-TEST-6 | T5-31, Q-TEST-6 | T5-31 fix; Q-TEST-6 closed by peer review | §22.13; §6.11 | resolved |
| Answer: Q-CTX-4 | T5-33, Q-CTX-4 | T5-33 decline (already fixed); Q-CTX-4 closed by peer review | §1.13; §9 D-SOCK-16; §23.6 M2 row | resolved |
| Answer: Q-KEYS-11 | T2-23, Q-KEYS-11 | T2-23 fix; Q-KEYS-11 closed by peer review | §10.6 retention; D-KEYS-20; §10.12 | resolved |
| Answer: Q-BRIDGE-2 | Q-BRIDGE-2 | closed by peer review | §17.14 | resolved |
| Answer: Q-SDK-5 | T3-20, Q-SDK-5 | T3-20 fix; Q-SDK-5 closed by peer review | §18.13; §4.4; D-SDK-20 | resolved |
| Answer: Q-OPS-5 | Q-OPS-5 | closed by peer review | §19.14 | resolved |
| Answer: Q-QUOTA-3 | T5-14, Q-QUOTA-3 | T5-14 fix; Q-QUOTA-3 closed by peer review | §20.9; D-QUOTA-9; §20.12 | resolved |
| Note: Decision 135's "validated" label is settled. A forward-confirmed PTR … | T4-10 | disclose | §15.5; §2.8 EX3; D-MAIL-13 | resolved |
| Disposition of R3 C1: Head commit does not cover the entry versions it names | T1-01, T1-02 | T1-01 fix-modified; T1-02 fix | §11.8 write rules, I-EVS-1..7; D-EVS-13; §11.8 Outcomes; D-EVS-23 | resolved (as R3 C1) |
| Disposition of R3 C2: Path-level success and a git ref are two histories | T1-05, T1-24 | T1-05 fix; Q-EVS-8 decided (owner decision 141); T1-24 decline (already fixed) | §11.7 modes; §11.11; D-EVS-22, -28; §11.8 parts; D-EVS-20 | resolved (as R3 C2) |
| Disposition of R3 C3: P0 schedule and the 7-day cap | T3-21 | fix | §7.4; §5.13; D-TRUST-3 | fixed (as R3 C3) |
| Disposition of R3 C4: Harness evidence is a self-signature | T3-05 | owner item, decided (owner decision 142) | §16.6; D-MCP-9; §16.12 Q-MCP-6 | disclosed (as R3 C4) |
| Disposition of R3 C5: A withheld removal is not bounded by 24 hours | T2-05, T2-06 | T2-05 disclose; T2-06 fix-modified | §2.8 exposure bound; §6.17; §6.4-§6.6; §8.10; D-PROTO-17, -18 | fixed (owner decision 147; rounds 5-6; as R3 C5) |
| Disposition of R3 C6: TLS 1.2 shows recipients to the edge, and the proof is a … | T4-01, T4-27 | T4-01 fix; T4-27 fix (test only; already fixed) | §14.5 Z7-Z9; D-SMTP-22; FS-31; D-SMTP-21 | resolved |
| Disposition of R3 C7: Site loss skips the sidecar dump, and the RPO sentence is … | T5-01, T5-03, T5-04 | all fix | §19.6; §19.10 recovery | resolved (as finding 5) |
| Before M2 1: Make the head `If-Match` the only read-modify-write, over … | T1-01, T1-02, T1-05 | T1-01 fix-modified; T1-02 fix; T1-05 fix; Q-EVS-8 decided (owner decision 141) | §11.8 write rules, I-EVS-1..7; §11.8 Outcomes; §11.7 modes | fixed (owner decision 148; rounds 5-6; as finding 1) |
| Before M2 2: Publish the witness residual §2.8 already states, and stop … | T2-05, T2-06 | T2-05 disclose; T2-06 fix-modified | §2.8 exposure bound; §6.17; §6.4-§6.6; §8.10; D-PROTO-17, -18 | fixed (owner decision 147; rounds 5-6; as finding 2) |
| Before M2 3: Take `harness` out of `evidenceDefault` until the hook peer … | T3-05 | owner item, decided (owner decision 142) | §16.6; D-MCP-9; §16.12 Q-MCP-6 | disclosed (as finding 3) |
| Before M2 4: Exclude a dropped agent's `ReaderKey` from the rotation … | T2-03, T2-04 | T2-03 fix; T2-04 disclose | §10.5 KeyHolders; D-KEYS-16; §2.9 I-15; §10.5 | resolved (as finding 4) |
| Before M2 5: Rewrite the RPO sentence and restore the sidecar dump in … | T5-01, T5-03 | all fix | §19.6; D-OPS-14; D-OPS-18 | resolved (as finding 5) |
| Before M2 6: Answer Q-EVS-6 with a head binding, and reserve pack … | T1-10, T1-20 | T1-10 fix-modified; T1-20 fix | §11.8 head; §11.9; D-EVS-24, -29; §11.6; §11.13; D-EVS-27 | disclosed (as the Q-EVS-6 answer) |
| Before M2 7: Keep the 0x0010 freeze at the exit review that has one … | T2-25, T5-23, T2-24 | T2-25 fix; T5-23 fix; T2-24 fix-modified | §10.4; §22.10; §10.5 | resolved (as the ladder major) |

## 5. Peer-review questions, closed with their conditions

Peer review was the decider for these eleven questions and for Q-QUOTA-3's residual, which owner decision 92 left to it. Each now carries "**Closed by peer review 2026-11-04:**" in its owning section, with the conditions below. None reopens an owner decision. Two conditions differ from the answers first drafted in peer/PEERQ.md, because owner decision 136 and the fix round changed them. They are marked *Changed since PEERQ*. The last column gives the final panel's verdict on each closure, as the final rounds changed it.

| Question | Answer | Conditions, as the text now states them | Gate | Where | Final |
|---|---|---|---|---|---|
| Q-TEST-1: copy connect's test helpers or export them? | (a) | `sidecartest` builds on connect's exported API only. Every T2 scenario that uses the fake contract issuer or the ControlId sink also runs in T3 on server's exchange, and a divergence fails the build. A connect pin change reruns both tiers. A recurring drift, or a helper that needs unexported state, raises an X9 row for `connect/connecttest` to the owner. R1, R1b and R2 chose (a); R3 and R3b chose (b). | M0 | §22.13 | resolved; R3's and R3b's (b) declined-as-stated |
| Q-TEST-2: how does the local stack match production? | (a) plus (b) | Locally: a 3-master Redis Cluster on 8.10.2, and one 8-drive MinIO at EC:4 from the production source. In T3 and at the release gate: the same cluster, and MinIO as 4 × 2 at EC:4 and 4 × 4 at EC:8. A runtime and static CROSSSLOT lint. Canary is no substitute. | M0 | §22.13, §22.4 | resolved |
| Q-CORE-4: must a sidecar prove possession of its ClientKey? | (b) in v0; (c) later | A DPoP proof (RFC 9449) by the ClientKey on refresh, the token exchange and `POST /network/auth-client`, for `strict_exp` bearers. The jti is single-use within 120 s, and `iat` must be within ±60 s. The key is the newest bound key, else the enrollment key. sdk hosts sign through `Api.SetDpopSigner` before D-CORE-8's core refresher is switched off. (c)'s residual is stated in §7.4: until then a copied token can authenticate a transport until `exp`, at most 7 days. | M1 | §5.13, §7.4 | resolved |
| Q-TEST-6: does the `oneof` ban cover every proto? | (b) | No `oneof` in envelope, stream or push messages, or anything they carry. §22.5's descriptor lint walks those roots, with an empty allowlist in v0. The reason is hot-path allocation, not `UrMlsCredential`, which has no oneof. | M1 | §22.13, §6.11 | resolved |
| Q-CTX-4: who designs `ur share`? | (a), §9 (D-SOCK-16) | A blinded `share/<token>` socket while `ur share` runs, with a 256-bit secret in the link's fragment. A durable use count under D-MCP-11's reserve-before-effect rule. Bytes count on the transfer balance. Availability ends when the sharer exits. (b) would have changed format 1. | M2 | §1.13, §9 | fixed: D-SOCK-16 now binds the expiry R1b and R2 asked for, 24 h by default and at most 30 days (6.1) |
| Q-KEYS-11: how long does GKM keep epoch objects? | (a) | 30 days, then until every leaf that acked in the last 30 days has applied them, on four conditions: (1) the newest epoch is never deleted, and the `group-info` pointer moves first; (2) generations, GroupInfo and recovery wraps live outside epochs; (3) a hold pauses the sweep; (4) §19.9 sizes the family at M2. *Changed since PEERQ:* acks are Redis soft state (owner decision 136), and the reconciler deletes only while the ack family has existed 30 days. *Residual:* §19.9's measured size. | M2 | §10.12, §10.6 | resolved |
| Q-EVS-6: must a head reader that does not replay verify freshness? | (c), made cheap | Head readers replay signed statements, not payloads, from their pin, and check the statement behind every entry they read. Statements are at most 1 KiB, with `changes_root` and proofs for larger change lists. Phones keep durable pins and catch up by at most 4 MiB, else re-pin with a gap mark. Config, mailcfg, the mailbox's `vault/` and `i/`, and approvals are mirrored and replayed in full. A head below a pin needs an EvsReseed. Disclosed: a never-read path's version at the first pin rests on evs; a HeadCheck confirms the pin, not that version (§11.17's closure now says so: SC-N7). Under T6, the head names statements by hash and batch place; the reply is unchanged. | M2 | §11.17, §11.9 | disclosed. New: SC-N5, SC-N7 and OT-N8 (fixed) |
| Q-OPS-2: should small objects pack? | (b) in v0; (a) a switch | Format 1 freezes content-id segment ids, the `spidx/` family and its lookup order, and reserved locator kinds 3 and 4, never a physical address. After §22.8's `hdd` row (M3; OT-N4), (a) turns on for segments under 1 MiB and older than 7 days, once HDD drive operations pass 50% of capacity. GETs, ~25,600 of year two's ~32,000 operations a second, go to the page cache and (c), more HDD sets. *Changed since PEERQ:* history packing follows owner decision 136 (after 24 h; a small repo's at 256 KiB or 7 d), not weekly; and gkm's `gen/` packs into §10.16's gen packs only from §19.9's gen trigger, not by a fixed date, the packs counting as `gen/` for shreds and re-seeds. | M2 | §19.14 | fixed: R1b's `gen/` packing now has a trigger and a shred and erasure rule (6.1). New: OT-N4 (fixed) |
| Q-BRIDGE-2: how do bridge links reach targets? | (c) | One `BridgeHost` link per target: a fixed `ProviderSpec{ClientId}` multi client with window size 1, PostQuantumEncryption Required, `OverrideAllowDirect=false` until C3, and `EnableIcmp`, never `DefaultMultiClientSettings`. Each window client carries the subject's WindowDelegation into C13's seal. (b) is adopted only where §22.9 measures per-target memory over the iOS budget and the new framing passes its tests. The iOS tunnel runs no link until measured. | M4 | §17.14 | resolved |
| Q-SDK-5: where does the iOS device role live? | (b) now | `sidecar/device` imports only connect and a generated `sidecar/protocol/bridge`, which imports only std and protobuf and holds what the role verifies. `make check` fails the ios_extension leg if it links the root or `protocol`. `make size`'s 1 MiB gate stays and passes at M4. §2.10 gains the routing-integrity row, and `device.Bridge` replaces `sidecar.Bridge`. | M4 | §18.13 | resolved; R1b's and R2's (a) declined-as-stated |
| Q-OPS-5: should `dns` deploy staged? | (a), staged | N and N+1 read each other's journal rows and snapshots, with N+1's unreadable writes gated until 100%. `dnsedge` stays single-pass, one host at a time, serving only self-checked snapshots. Rollout stops on a canary failure or a serial divergence. FS-52 rolls back in T3. | M5 | §19.14 | resolved |
| Q-QUOTA-3's residual: the credit line's draw order | one comparator | `escrowDrawLess` (credit last, then end time, start time, balance id) orders every draw, and returns run in reverse (D-QUOTA-9). Invariants E-a to E-e are tested by FS-46. The benchmark at 2× year one: p99 admission and settlement within 5% of main, and no added Postgres round trip. Both gate M6's entry. | M6 | §20.12, §20.9 | resolved. New: OT-N3 (fixed) |

## 6. Remaining open items and verification gaps

The final panel marks no finding open. Sections 6.1 and 6.2 list what it left, 24 findings partial and 61 new issues, 10 of them major, each with its final status after rounds 3 to 6 and the major re-checks (sections 6.7 and 6.8). None stays partial. Rounds 3 and 4 left seven findings and four majors partial: the close-out build resolved the finding through the front matter, and rounds 5 and 6 fixed the majors SL-N1, WR-N1, ST-N1 and AU-N2 and the six findings through them (section 6.8).
- **Final:** as section 1 defines it. A *fixed* item waits for a reviewer's re-check at its gate. *(R4)* marks a fix that round 4 changed again after the major re-check or the cross-section check, which no reviewer has read since.
- **Decider:** the sections whose editors settle the item; the owner only where a decision or its record is touched. For a fixed item, where to re-check it.
- **By:** the review gate where the item must be settled (§23.8): G0 for text and for closures of the questions in §23.6's M0-M2 rows; otherwise the entry review (Gn-in) of the milestone whose design closure in §23.6 holds the mechanism.

### 6.1 Findings the panel marks partial

| Findings | Entry | Final | What remains | Decider | By |
|---|---|---|---|---|---|
| R3b finding 1 (the storage-tier cluster; the storage-commit cluster found it resolved) | T1-01 | fixed (owner decision 148; rounds 5-6) | Nothing. As ST-N1 (6.2): removal folds write versioned tombstone markers with If-Match, never blind deletes, so no late or redundant fold deletes an entry a later fold wrote. | §11, §22 | M2-in |
| D-EVS-31, lazy folds | §3.6 | fixed (owner decision 148; rounds 5-6) | Nothing. As above (ST-N1). | §11, §22 | M2-in |
| R1b F08; R3's path-tokens major | T1-07 | fixed (R4); the path-tokens major resolved | Nothing. SL-N2 re-checked resolved, its checker's follow-ups fixed in round 4; SL-N3 fixed; batched epochs alarm 1 h past due, and D-EVS-12 reads "due within 24 h". | §11, §22 | M2-in |
| R1b C05 | T1-16, T5-12 | fixed (owner decision 146; rounds 5-6) | Nothing. As SL-N1 (6.2): the closure allowance is per eraser, with a floor §21 cannot lower; §11 states it and its 429, and FS-47 queues a CLOSURE past the rate as P1. SL-N6 and the disclosure that v0 erasure frees no stored bytes are fixed. | §11, §20, §15, §21, §22 | M2-in |
| R1b S11 | T5-02 | fixed | Nothing (SL-N4). | §19, §22 | G0 |
| R1b F03; R1 F05 | T2-13 | fixed (R4) | Nothing. AU-N1 re-checked resolved; FS-19 adds the invite, quick-burner, admin, tag, Delegation and add-then-remove runs, which round 4 gated by feature from M2 to M8. | §8, §22 | M4-in |
| R3's Q-TEAM-10 (a) major | T2-18 | fixed (owner decision 149; rounds 5-6) | Nothing. As AU-N2 (6.2): a void re-seals keychain.wrap and re-enrolls exposed backups, and a restored binding's scoped admission activates through the 72 h window with admin veto. AU-N3 is fixed. | §5, §7, §10, §18, §22 | M2-in |
| R3b finding 2; R3 C5 | T2-05, T2-06 | fixed (owner decision 147; rounds 5-6) | Nothing. As WR-N1 (6.2): phones keep their newest 64 KiB of authorization-log entries and serve proofs, and FS-17 and §6.16 now say so. WR-N2 and WR-N3 are fixed. | §22, §6 | M2-in |
| R1b C04 | T2-21 | fixed (R4) | Nothing (WR-N7). | §10, §22, §5 | M2-in |
| R1 F06 | T1-22, T2-12 | fixed (R4) | Nothing. §5.9, §7.9 and §10.8 say that no rebind reaches an earlier keychain backup, and each device whose backups may be exposed is revoked as compromised and enrolled anew. Related: AU-N2's keychain.wrap gap, now fixed (owner decision 149; rounds 5-6), which extends the rule to voided bindings. | §5, §7 | G0 |
| R3's HNDL major | T2-24 | fixed | Nothing (WR-N3, WR-N8). | §10 | G0 |
| R1b F13; R1 F19; R2 F14 | T3-07 | fixed | Nothing. A change counts as the run's edit only when the run's before- and after-hashes chain across the scan; the restore suite and FS-26 add a hand edit before the run's edit. | §16, §22 | M3-in |
| R3 C3 | T3-21 | fixed (R4) | Nothing. §7.4's stage 2 waits for the extension release that stops persisting `by_jwt`, which round 4 scheduled (§23.7), and `ur` refuses to enroll beside it (§5.6). | §7, §18, §5 | M1-in |
| R3's "§6 is not a wire spec" major | T4-18 | fixed (R4) | Nothing. §6.5-§6.7 define the stream offsets, the windows and a response's type, and §9.4 K's labels and the listing seal; round 4 added §22.5's vectors. | §6, §9 | M2-in |
| R3's platform-listener major | T4-11 | resolved (close-out build) | Nothing. The front matter's X6 row and Appendix A's D-MAIL-1 row now name D-MAIL-10's listener, as D-MAIL-1 and the requirement rows do. | — | — |
| Q-CTX-4, as R1b and R2 asked | Q-CTX-4 | fixed (R4) | Nothing. D-SOCK-16 binds an expiry, 24 h by default and at most 30 days, and round 4 added it to Q-CTX-4's closure (§1.13). | §9, with peer review | G0 |
| Q-OPS-2, as R1b asked | T1-20 | fixed (R4) | Nothing. `gen/` takes §10.16's gen packs from §19.9's gen trigger, counted as `gen/` for shreds and re-seeds; round 4 added them to gkm-7. | §19, §10, with peer review | G0 |
| CRITIC4 Major 6 | T5-01, T5-03, T5-04 | fixed | Nothing. OT-N1 and OT-N2 re-checked resolved, with minor leftovers (6.2); OT-N7 fixed. | §19, §12, §22 | M3-in |

### 6.2 New issues the panel found

Ids name the panel's cluster and its own number (peer/FINAL-*.md): SC storage-commit, SL storage-lifecycle, ST storage-tier, AU authority, WR witness-recovery, RT runtime, EM edges-mail, OT ops-test-phase.

| Id | Severity | Entry | Final | Issue, and what remains | Decider | By |
|---|---|---|---|---|---|---|
| SC-N1 | major | T1-02, T1-05 | resolved | A fence, seal lease or source drop gave a warm-cache git push a false 409. The 412 row's git branch now decides by version, and leases set no fence_ms (§11.8; FS-5). Round 4 fixed its checker's three minor follow-ups: the lease's own head CAS, the costs row and §11.19's FS-1 ask. | §11, §22 | M2-in |
| SC-N2 | minor | T1-17, T1-24 | fixed | The seal's re-check skipped 5g's directory rules. It now reruns 5g per part, merges directory deltas and checks the bound (§11.8 seal row; FS-9). | §11, §22 | M2-in |
| SC-N3 | minor | T1-02 | fixed (R4) | Fences compared unsynced clocks; chrony now runs on the evs, gkm and taskworker hosts, and evs answers pushes 503 past a 50 ms offset (§11.8, §19.6; FS-1); round 4 gated taskworker's fences too and put chrony on the Redis masters' hosts. | §11, §19, §22 | M2-in |
| SC-N4 | minor | T1-02 | fixed (R4) | A refusal fence ended every concurrent push. A refusal now relies on a recent fence, at most one a second per ref, and leases set no fence_ms (§11.8; D-EVS-23; §11.20; FS-1); round 4 reconciled §11.19's FS-1 ask on seals with the fence row. | §11 | M2-in |
| SC-N5 | minor | T1-10 | fixed | Proving a path unchanged needed a push's whole change list. Changes are sorted, adjacent-leaf proofs show absence, and the 4 MiB budget counts proofs (§11.6, §11.9, §11.14; FS-10). | §11, §22 | M2-in |
| SC-N6 | minor | T1-06, T1-12 | fixed | Shred phase 1 now waits 20 s, outlasting §19.6's request deadline (§11.12, §19.6). | §11, §10, §19 | M2-in |
| SC-N7 | minor | T1-10 | fixed (R4) | §11.17's Q-EVS-6 closure ended "Residual: none". It now names its limit, that a HeadCheck confirms the pin and not a never-read path's version, and FS-10 serves a refused push's entry as current; round 4 aligned §11.9's trusts row with §2.8. | §11, §2, §22 | G0 |
| SL-N1 | major | T1-13, T1-16, T5-12 | fixed (owner decision 146; rounds 5-6) | Rounds 3 and 4 let an erasure's CLOSURE push and its `?closure=1` uploads through at the limit, bounded by rate, size and a daily allowance, but the allowance was network-wide, so one admin's CLOSUREs could make other erasures wait; §11 never named it, and FS-47 expected 429 for a CLOSURE push that §11.12 queues as P1. Now the allowance is per eraser, with a floor: each erasing sidecar has its own UTC-day `evs_closure_bytes_per_day` and 60 closure uploads a minute, which §21 may tighten but never below `evs_closure_bytes_floor`; FS-47 queues the push as P1, and §11.13 and §15.7 state the wait at the floor (§11.12, §11.19, §20.4, §20.7, §21.16; D-EVS-26). Residuals: section 6.8. | §11, §20, §15, §21, §22 | M2-in |
| SL-N2 | major | T1-07 | resolved | The path-epoch copy skipped directories a fold had moved. A fold now carries the source's rows, each tagged with its epoch, and the copy replaces them on its 412 path (§11.6 copy and read rows; EvsName.epoch; FS-4). Its checker raised six more issues, one major: a path removed during a copy came back. Round 4 fixed them with removed entries (§11.7; evs-11), and no reviewer has re-checked those fixes. | §11, §22 | M2-in |
| SL-N3 | minor | T1-07 | fixed (R4) | Steady creation could starve a PATH_EPOCH. A path tail and a creation block of at most 2 min let it land, batched epochs alarm 1 h past due, and D-EVS-12 reads "due within 24 h" (§11.6; FS-4); round 4 added the new head fields to §2.8's evs-3 and evs-12. | §11, §22 | M2-in |
| SL-N4 | minor | T5-01, T5-02 | fixed | D-OPS-14 gave a second host RPO 0 by set state. §19.6 now judges each object by its shards, and FS-40 adds a write that misses a drive with every host up. | §19, §22 | G0 |
| SL-N5 | minor | T1-14, T5-05 | fixed | §19.10's re-seed refused undefined "covered segments"; it now refuses only slot keys an applied erasure covers. | §19, §11 | G0 |
| SL-N6 | minor | T1-16, T5-12 | fixed (R4) | §11.13 and §20.7 disagreed on uploads at the limit; both now refuse segment uploads but re-seed and closure ones. Round 4 gave the refusal an answer on evs's routes and D-EVS-16 the config and mailcfg exception. | §11, §20 | M2-in |
| SL-N7 | minor | T1-17 | fixed (R4) | The 448 KiB cap had three wordings and could not hold 4,096 real names. One wording and a sealed-name size rule make bytes bind at 3,584 children, §15.7 and §16.8 size by bytes, and FS-9 uses real names; round 4 counted EvsName.epoch in carried rows. | §11, §15, §16, §22 | M2-in |
| AU-N1 | major | T2-13 | resolved | The ephemeral ceiling dropped the config read for uncovered ephemeral sidecars; §8.6 now passes the config kind default's read row (D-ACL-19; FS-19). Round 4 fixed its checker's five minor follow-ups: FS-19's gates and cases, member invites, and wording in §3.6, §7.9, §10.14 and §18. | §8, §22 | M4-in |
| AU-N2 | major | T2-18 | fixed (owner decision 149; rounds 5-6) | Rounds 3 and 4 parked the closure P from `since_n` and voided the RecoveryBinds, Rebinds, KeyRegisters and EvsShares it signed, but a void did not re-seal keychain.wrap, and a binding a void restored gave a scoped admission no path through the 72 h window. Now such an admission is a recovery AuthorityProposal that activates 72 h after its entry unless an AdminSet device vetoes it, shown as `recovery_window`; the cascade re-seals keychain.wrap, each device whose backups may hold a sealing to the voided binding is revoked for compromise and enrolled anew, and the admitted device anchors on a config ReaderWrap in §7.9's restored order (§7.9, §5.6, §5.9, §10.8, §18.5; D-TEAM-21, D-TEAM-26; §22.7; FS-16). Residuals: section 6.8. | §5, §7, §10, §18, §22, §2 | M2-in |
| AU-N3 | minor | T2-18 | fixed (R4) | The cascade's "header time" was undefined. The cut-off is `since_n`, a log position counted from the carrying entry (§7.9; D-TEAM-26); round 4 aligned §5.6. | §7 | M2-in |
| AU-N4 | minor | T2-01, T2-10 | fixed | A statement's `at` could lie beyond what readers keep; readers and api now refuse an `at` older than the retention point (§7.9; D-TEAM-20; FS-14). | §7, §22 | M2-in |
| AU-N5 | minor | T2-14, T2-20 | fixed | §10.6 now says "an r, rw or admin scope". | §10 | G0 |
| AU-N6 | minor | T2-01, T2-28 | fixed | Site-loss adoption's one-member exception counts only uploading devices (§7.9, §19.10; FS-41). | §7, §19, §22 | M3-in |
| AU-N7 | minor | T2-26 | fixed (R4) | The ShareKey sat unrotated in the config. It is now an owner-bound `secret` of Y's approving admin, which certifies a ShareSigner per config generation under 7-day ShareCerts (§17.9; D-BRIDGE-17; §2.10); round 4 registered ShareCert and the signer records (§6.9, §6.11, §4.4, §7.9, §2.6) and gave the keyless role a channel (§18.6). | §17, §8, §2 | M6-in |
| AU-N8 | minor | T2-33 | fixed (R4) | A restored config leaf ranks last and, if unentitled, leaves at the next leaf commit (§7.9 move row; §10.9's Remove input; D-TEAM-18), and §5.6 drops "or expired"; round 4 aligned §3.7's F1, §8.12 and OwnerConfirm's reset of live_since. | §7, §10, §5 | M2-in |
| AU-N9 | minor | T2-04 | fixed | §16.9 now says the Delegation's reader key reads on until its drop causes (§10.5). | §16 | G0 |
| AU-N10 | minor | T2-22 | fixed | §3.7's F3 step 7, and F9 step 4, hint on the writers' per-client gkm topic. | §3 | G0 |
| AU-N11 | minor | T2-19, T2-20 | fixed | FS-23's deposit-only cases gate at M2-out and its mailbox case at M7-out (§22.8, §23.6). | §22, §23 | M2-in |
| WR-N1 | major | T2-05, T2-06 | fixed (owner decision 147; rounds 5-6) | Rounds 3 and 4 added HeadCheck.proven and a relayed UNVERIFIED pin whose path holds at most 8 sidecars, and published the 8-hop bound (§6.4, §6.5; §2.8; D-TRUST-10), but FS-17's phone-holder case and §6.16 expected a phone R to keep no entries, against §7.9's retain row. Now phones keep their newest 64 KiB of authorization-log entries and serve the proof: X sends `proven` and W stops at once, and NOT_FOUND, `unverified` and witness_bound_hours apply only to a gap wider than R's kept entries (§6.4's auth row, §6.16, §6.17; D-PROTO-17; FS-17). | §22, §6 | M2-in |
| WR-N2 | minor | T2-06 | fixed (R4) | A higher pin whose proof never came raised nothing. It now alarms UNVERIFIED and stops witnessed_at refreshes; round 4 carried the pin on the wire and gave the alarms event kinds (§6.4, §6.5, §5.4, §18.5). | §6, §22 | M2-in |
| WR-N3 | minor | T2-05, T2-24 | fixed | Q-TRUST-9 and Q-KEYS-2 state their residuals, and D-TEAM-17 and §8.7 qualify "visibly". | §2, §10, §7, §8 | G0 |
| WR-N4 | minor | T2-08 | fixed (R4) | The window bounds admission, not what the code reads. §2.6 and §2.10 say the code reads its wraps at once, and D-TEAM-21 says "no key to the proposed device"; round 4 gave Q-KEYS-7 and Q-TEAM-11 the same residual. | §2, §7, §10 | G0 |
| WR-N5 | minor | T2-08 | fixed (R4) | A backdated veto could fork every reader; a veto kept off the log now forks only devices that held it before the activation (§7.9; D-TEAM-21). Round 4 added the case to §22. | §7, §6 | M2-in |
| WR-N6 | minor | T2-24 | fixed (R4) | The post-compromise bound omitted KEKs until the device's own path commit and a re-signed ReaderKey. A ReaderKey is now a fresh pair every 7 days, and §10.5 and §2.10 put the heal point after both events, about 37 days after a copy (60 above 50 leaves); round 4 aligned §7.9's expiry row. | §10, §2, §5 | M2-in |
| WR-N7 | minor | T2-09, T2-21 | fixed (R4) | KF1 writes the first RecoveryWraps before activation, a later commit heals the `group-info` pointer, FS-20 kills both boundaries, and §5.9 cites §10.8's limit; round 4 aligned §10.14's FS-20 ask. | §10, §22, §5 | M2-in |
| WR-N8 | minor | T2-25, T5-23 | fixed | A gap in a step the 0x0010 artifact requires holds the freeze unless a second peer covers that step (§10.4, §22.10, §23.8). | §22, §10, §23 | M2-in |
| WR-N9 | minor | T2-08, T2-09 | fixed (R4) | A code-only recovered device's genesis rested on what api serves; it now checks §7.9's anchor before any write (EX5; §5.6). Round 4 rebuilt the anchor after the cross-section check found seven majors in it: stated two ways, gating too little, resting on a recovery key every config reader holds, and absent from §10.8. | §7, §5, §2, §10 | M2-in |
| RT-N1 | major | T3-09 | resolved | MCP's evs tools reached `secret` repos and the config's keys. Every evs tool now refuses kind secret, reads of the config are refused (§16.5, §16.6; D-MCP-17), and §22.7's actions row and §22.15's testHookSecret sites test it. Optional wording left: D-MCP-17 says the tools "never read the config repo", where §16.6 refuses only reads of its contents, and §16.6 calls config files "records". | §16 | G0 |
| RT-N2 | minor | T3-09 | fixed (R4) | A host's first BridgeAddress could not be filed through MCP; §16.6, §5.8, D-MCP-17 and §17.9 now admit it. Round 4 added the §22.7 refusal cases. | §16, §5, §17, §22 | M4-in |
| RT-N3 | minor | T3-01, T3-09 | fixed | bridge_expose returns §17.8's rule id, and bridge_close takes either (§16.5, §17.9). | §16, §17 | M4-in |
| RT-N4 | minor | T3-16 | fixed | WK2 now names every way a wake is lost, and counts the failed XADDs (§18.7; FS-36). | §18, §22 | M8-in |
| RT-N5 | minor | T3-16 | fixed (R4) | Losing a master that did not hold the one sentinel lost its tokens; a sentinel per slot now re-projects them (§18.7; FS-36). Round 4 listed the sentinels in §2.8's api-6. | §18, §19, §22 | M8-in |
| RT-N6 | minor | T3-02, T3-08 | fixed (R4) | A decision approved before taint kept spending; the daemon now refuses it as stale and files a tainted request (§16.6, §5.4; §22.7). Round 4 aligned §3.7's F8. | §16, §5, §22 | M3-in |
| RT-N7 | minor | T3-12 | fixed (R4) | A receipt-only depositor's other entries had no enforcement point; ingest consumes them unread, with an alarm (§11.12; FS-30). Round 4 added the alarm to §16.8 and D-MCP-18. | §11, §16, §22 | M3-in |
| RT-N8 | minor | T3-18 | fixed | Two tabs ran two Workers on one keychain; only the holder of a per-network Web Lock loads state, and the others relay (§18.8; §22.9). | §18, §22 | M4-in |
| EM-N1 | minor | T4-09 | fixed | ext-3 now names receivers' reception-time lookups (D-MAIL-14). | §2, §15 | G0 |
| EM-N2 | minor | T4-10, T4-28 | fixed | Burner mail from an operator listed only for MTA-STS stays "validated" under owner decision 135, and §15.5, §15.16, EX3 and §2.18 now say that no policy applies to it; §22.7 tests the label's basis. | §15, §2, §22; the owner for the second option | M7-in |
| EM-N3 | minor | T4-04 | fixed (R4) | Strong mode's ALIAS could flatten CAA. It now flattens A and AAAA only, with a canary CAA checked at setup and renewal (§12.8, §13.8; FS-32); round 4 defined the apex target, the probe's pending state and the compelled-operator risk. | §12, §13, §2, §22 | M6-in |
| EM-N4 | minor | T4-01, T4-27 | fixed | The relation's public inputs now include the handshake values Z1 binds to (§14.5). | §14 | M9-in |
| OT-N1 | major | T5-01, T5-03, T5-04 | resolved | §19.10 dropped rows newer than the main dump. D-OPS-18 now carries their parent rows, and the restore follows the newer dump by snapshot time (§19.6, §19.10; FI-12; FS-42). Minor leftovers: §7.10's api row says "after the main dump's snapshot" where §19.10 says the older dump's; FS-42's M7 and M9 cases lack a revocation between the dumps when the main dump is newer; FI-12 omits the clients deactivated to re-enroll. | §7, §19, §22 | M3-in |
| OT-N2 | major | T5-04 | resolved | A Postgres-only restore left the zone serial and journal behind the edges. §12.6's restore step holds dns writes, sets restore_serial above every serial issued and lists changed RRsets, and §19.10 runs it before api's replay (FS-42, M5 to M9). Minor leftovers: §7.10's wording, as in OT-N1, and the owners §12.6 cannot map to a network through the restored dns_label, which nothing lists. | §7, §12, §22 | M5-in |
| OT-N3 | minor | T5-14, T5-22 | fixed (R4) | No milestone built the escrow evidence. M4 builds the comparator dark, and D-PHASE-7 names this entry gate as the one that runs code (§23.4, §23.8, §20.16); round 4 put the index in MG6, pending until M6's Gn-out. | §23, §20, §22 | M4-in |
| OT-N4 | minor | T1-20, T5-29 | fixed | Q-OPS-2 now cites §22.8's `hdd` row (M3). | §19, §22 | G0 |
| OT-N5 | minor | T1-15, T5-13 | fixed (R4) | FI-13(c) and FS-60 subtract hold-only objects and superseded containers; round 4 aligned §11.13's bytes row and evs-9. | §22, §20 | M2-in |
| OT-N6 | minor | T5-03, T5-07 | fixed | §19.6 states the primary-loss RTO, no target beyond the platform's restore and §19.10's reconcile, and §19.17 adds its risk row. | §19 | M3-in |
| OT-N7 | minor | T5-03 | fixed | Q-OPS-3's residual is marked closed by peer review, with OT-N1's bound. | §19 | G0 |
| OT-N8 | minor | T1-10 | fixed (R4) | §2.8 now says a re-pin past §11.9's 4 MiB budget takes every path's version on evs's word; round 4 aligned §11.9's trusts row and Q-EVS-6. | §2, §11 | G0 |
| OT-N9 | minor | T5-07, T5-18 | fixed | FS-50 keeps its pager case at T3, and its out-of-hours host return is §22.8's production `hosts` row. | §22 | M3-in |
| ST-N1 | major | T1-01, T1-03 | fixed (owner decision 148; rounds 5-6) | Rounds 3 and 4 read the head before entries and added I-EVS-8 and FI-15 (§11.7-§11.9), but a late or redundant removal fold could still delete an entry a later fold wrote, and entry versions restarted after a delete, so a stale push passed 5g. Now removal folds write versioned tombstone markers with If-Match, never blind deletes: a marker {removing push id, r, the path's version} goes only over an entry holding an older version, a re-created path's versions continue from it, and taskworker deletes markers only in collect windows a head CAS opens, once folded_through ≥ r + 64 (§11.7, §11.8, I-EVS-8; D-EVS-31; §2.8 evs-3, evs-11; FI-15, FS-58; D-OPS-20). Residuals: section 6.8. | §11, §22, §19, §2 | M2-in |
| ST-N2 | minor | §3.6 | fixed (R4) | §11.13 and §19.6 now read "3.7-4.0 DWPD at the ~1-1.6 records a batch of a set near capacity"; round 4 aligned §19.9's pb/ row. | §11, §19 | G0 |
| ST-N3 | minor | §3.6 | fixed | R-EVS-15 says 3-5 store round trips. | §11 | G0 |
| ST-N4 | minor | §3.6 | fixed | The byte bucket's 512 B sector bound caps writes near 39% of rated IOPS, T is defined, and FI-14 excepts a drive under heal (§11.13, §19.6). | §11, §19, §22 | M2-in |
| ST-N5 | minor | §3.6 | fixed | `{evsh_}` serves each head only within 10 min of its own cache time (§11.9; evs-24; FS-62). | §11, §2 | M2-in |
| ST-N6 | minor | §3.6 | already fixed | Owner decision 145's record was corrected 2026-11-04, as decision 140's was: ~400-450 pushes/s a set once load spans clusters and five to six sets in year two. Section 2.4 says so, and the 2026-11-05 close-out build's front matter and §19's Q-OPS-10 carry the corrected sizing. | — | — |

**Also from the assembly.** The seventh assembly's report (review/ASSEMBLY7.md, "Problems not fixed") added three section gaps, each a text edit by G0. Round 3 fixed all three:
- §2.8's api-7 and §19.7's `{acl_}` tag omitted the `{acl_}q` counter that §7.17 says api-7 lists; both now list it (§2, §7, §19);
- §20.4's pro.yml lacked the authorization log's append limits that §7.9 puts there; it now carries them (§20, §7);
- §11.19 said §23.7 sizes year two at five to six sets, though §23.7 gives no count; it now cites §19.9 (§11, §23).

Its fourth, a host's BridgeAddress, is RT-N2.

### 6.3 Q-EVS-9, closed (owner decisions 2, 140, 145)

The fix round raised Q-EVS-9 in §11.17, in answer to VERIFY-T6's finding that owner decision 140's ~10-15 KiB per push target was silently unmet.
- **The problem.** Owner decision 2's commit point is the head's If-Match overwrite. That overwrite alone writes ~14 KiB on each drive (~10.5 KiB on 1 KiB blocks), because MinIO also rewrites the old `xl.meta`.
- **Closed (owner decision 140, record corrected 2026-11-04).** The ~10-15 KiB of drive writes a push in the record was the design team's first estimate, not the owner's requirement, which is the PM9A3 profile itself ("We have to make that iop profile work"). The binding target is the drive budget: at most 0.8 DWPD and at most 50% of rated IOPS per drive at the design load. The design meets it at about 27-43 KiB per push, and D-TEST-11 gates format 1 on at most 43 KiB per push per drive. That was option (a).
- **Not taken:** (b) a head per version, created If-None-Match, which departs from owner decision 2's If-Match commit point; (c) patching MinIO to skip the old `xl.meta` copy, which gives up its torn-write backup.
- **Text.** §11.13, §11.17, D-TEST-11 and §23.6 record the closure, so §1.9's, §3.1's and §23.6's statements that no owner question is open hold. The storage-tier cluster found it resolved.

### 6.4 Verification: the verifiers, FIX3 and the final panel

Seven verification reports checked the first edit pass against the registers, the briefs, the orders and owner decisions 1-145. The fix round then edited 22 of the 23 section files (2026-11-04, 18:44-19:51); §1 was not touched.

| Report | Blockers | Majors | Minors | Entries the verifier marked partial, wrong or missing |
|---|---:|---:|---:|---|
| VERIFY-T1 (storage) | 1 | 7 | 12 | T1-02, T1-03, T1-04, T1-05, T1-06, T1-07, T1-12 |
| VERIFY-T2 (authority, keys) | 3 | 5 | 5 | T2-01, T2-03, T2-08, T2-09, T2-12, T2-33, Q-KEYS-15 |
| VERIFY-T3 (runtime) | 0 | 5 | 9 | T3-01, T3-09, T3-12, T3-17, T3-19, T3-20 |
| VERIFY-T4 (edges, mail, network) | 0 | 3 | 15 | T4-14, T4-20, T4-23 |
| VERIFY-T5 (ops, tests, phasing) | 0 | 3 | 9 | T5-03, T5-04, T5-14, T5-22, Q-QUOTA-3's residual |
| VERIFY-T6 (storage tier) | 2 | 4 | 14 | owner decisions 136, 140 and 145 partial; addenda EVS-T6-18 and EVS-T6-19 wrong; ten addenda items partial |
| VERIFY-XS (cross-section) | 1 | 5 | 14 | owner decision 144 wrong; R-14, R-15, T3-01, T3-20, T3-25, T5-14, T5-18 and owner decisions 133, 136 and 145 partial; T1-20's Q-OPS-2 conditions missing |

The reports overlap.
- VERIFY-XS's blocker (three config-group leaf rules) is VERIFY-T2's first blocker.
- XS majors 2, 3 and 6 repeat VERIFY-T6 major 4, VERIFY-T3 major 4, and VERIFY-T5 majors 2 and 3 with VERIFY-T6 minor 18.

The blockers, all addressed in the text:
- **Git-mode FORCE and PATH_EPOCH.** Git-mode refs commit by TIP for every push, and replay excepts FORCE from descent (§11.7).
- **One leaves rule.** §7.9's rule is the only one; §5.6, §8.12 and §10.4 cite it.
- **Expiry rotations.** A rotation covering an authorization expiry is cause REMOVE (§10.9).
- **Recovery window.** It runs from the newest recovery-key signature, so a late cosign restarts it (§7.9).
- **The P2 cap.** It is replaced by a pre-paid, work-conserving floor (§11.13).
- **`pidx/` keys.** They are container-keyed (§11.13).

**What we checked.** We compared each of the 117 issues with the edited sections and found the fix text in place for every one, except two outside the sections, now settled (6.5). Where the fix round chose between the verifier's options, the choice is in the text:
- `gen/` stays unpacked, so the Q-OPS-2 clause was struck (XS major 5);
- read receipts ship at M3 (VERIFY-T3 minor 8);
- control contracts ship at M4 (VERIFY-T2 minor 10);
- large socket sets register in pages (VERIFY-T4 major 3);
- the per-push target became Q-EVS-9 (VERIFY-T6 major 6), since closed (6.3).

**Re-verification.** REVERIFY-T1 to T6 and REVERIFY-XS re-ran on the edited sections (2026-11-04), the mechanisms the fix round added included. Of 118 items they found 92 resolved, 25 partial and 1 missing. They raised 30 issues and 34 regressions, 6 of them major.

**FIX3.** It applied 168 fixes to 22 section files (2026-11-04 23:07 to 2026-11-05 00:02); §1 was not touched. Where it took another option, or left a part to the section that owns it, FIX3.json gives the reason.

**The final panel.** Eight clusters re-checked, against the section files after FIX3, the five reviews' findings, CRITIC4's majors, the storage-tier decisions and the re-verification items (peer/FINAL-*.md, 2026-11-05).

| Cluster | Checks | Resolved | Partial | Disclosed | Declined as stated | New issues (major) |
|---|---:|---:|---:|---:|---:|---:|
| storage-commit (SC) | 20 | 18 | 0 | 2 | 0 | 7 (1) |
| storage-lifecycle (SL) | 21 | 15 | 4 | 2 | 0 | 7 (2) |
| storage-tier (ST) | 30 | 28 | 2 | 0 | 0 | 6 (1) |
| authority (AU) | 21 | 17 | 3 | 1 | 0 | 11 (2) |
| witness-recovery (WR) | 17 | 9 | 5 | 3 | 0 | 9 (1) |
| runtime (RT) | 38 | 30 | 4 | 3 | 1 | 8 (1) |
| edges-mail (EM) | 52 | 45 | 2 | 5 | 0 | 4 (0) |
| ops-test-phase (OT) | 76 | 62 | 4 | 6 | 4 | 9 (2) |
| **Total** | **275** | **224** | **24** | **22** | **5** | **61 (10)** |

- None is open.
- Some findings were checked by two clusters. Where they differ, this file takes the weaker status: R3b finding 1 (resolved for commit, partial for the tier) and R3's path-tokens major (partial for the lifecycle, resolved for ops).
- The runtime, authority, edges-mail, ops-test-phase and storage-tier clusters state that every re-verification issue and regression in their scope is fixed in the text.

### 6.5 Outside the 23 section files

- **Front matter and appendices.** The revised DESIGN.md's, generated by the final build, carry:
  - FRONT-1: the directive's inbound-mail bullet names the report listener, which "parses headers and aggregate report data only";
  - Appendix B: Q-EVS-9 decided, and no question open;
  - Appendix G: a pointer to §2.8 with a census (T5-30);
  - the "contradicts a decision" sentence, with owner decision 114's exception (T2-04) and owner decision 145's sizing;
  - "Other families": FI, FS, RV and WK.
  - **Fixed in the 2026-11-05 close-out build** (assembler data and one §19 sentence; the build validates cleanly):
    - the X6 row and Appendix A's D-MAIL-1 row name D-MAIL-10's report listener (T4-11);
    - the "contradicts a decision" sentence, owner decision 145's row and §19's Q-OPS-10 give the corrected sizing (ST-N6);
    - "Other families" gives FI-1 to FI-15 and I-EVS-1 to I-EVS-8 (ST-N1).
- **Ids.** R-PHASE-11 and R-PHASE-12 (§23.2) were allocated by no order (VERIFY-T5 issue 12). FIX3 kept them: they collide with nothing, and the assembler's id check passes.
- **Owner decision 145's record** was corrected 2026-11-04, as decision 140's was (ST-N6). It keeps T6's single-stream ~490-650 pushes/s for the first set alone, and gives ~400-450 a set once load spans clusters and five to six sets in year two.
- **The assembly's word table** (review/ASSEMBLY7.md) still measures OUTLINE's ceilings, which §23.8's G0 no longer applies (T5-30).

### 6.6 Evidence the design still waits for

These are gates by design, not defects. Every throughput, endurance and capacity figure in §11.13, §19.6 and §19.9 is a model inference until these runs replace it. That includes:
- the per-set capacity of ~400-450 pushes/s, which falls to ~310-330 at the model's high constants (§11.20);
- year two's five to six clusters;
- the 40% P2 floor.

| When | Evidence | Owner |
|---|---|---|
| M0 | §10.4's MLS subset and KAT start; D-OPS-18's dump and the main dump's exclude list from MG0's Gn-out | §10, §19 |
| M2 entry | `EvsCommit.tla` passing TLC, with ST-N1's file-mode CAS invariant; the FS rows written as tests; vector schemas; RECORD.md reviewed | §22, §11, §16 |
| M2 exit | D-TEST-11's `nvme` run on the PM9A3 set (bytes per push, per-operation costs, 4 KiB against 1 KiB blocks), with the `fold` and `trash` rows (fold ratio, records per batch per cluster, records per parcel); the model puts 4 KiB blocks at 43.5 KiB a push, just over the gate, and 1 KiB blocks at 33.3, so the gate will likely pick 1 KiB, and a miss there has no named lever but waiting (§22.16); §10.6's sizes and §19.9's epoch size (Q-KEYS-11's residual); the 0x0010 interop artifact; the M2 schedules | §22, §11, §10 |
| M3 | the `hdd` row before the segment cluster holds data, which Q-OPS-2's switch reads; FS-40 on production with heal throughput; the `nvme` run again on production; the production `hosts` row, FS-50's out-of-hours drill; a sidecar-dump restore drill before the pilot | §19, §22 |
| M4 | `make size`'s 1 MiB gate; §22.9's per-target memory before any iOS bridge link | §18, §17 |
| M5 | counsel confirms owner decision 133's condition and each hold kind's applicability | §21, §23.7 |
| M6 entry | FS-46 and §20.9's benchmark on the comparator M4 builds dark (OT-N3) | §20 |
| BS1 | the owner accepts the SNI loss M7's census finds (owner decision 34; D-MAIL-9) | the owner |
| M9 | `smtpproof/SPEC.md`, two non-authors' soundness argument and the independent relation checker | §14, §22.10 |

### 6.7 Final rounds (2026-11-05)

- **Round 3.** A fix round on the panel's 61 new issues, its 24 partial findings and 5 assembly cross-checks (peer/FINAL-OUTCOMES.json): 214 items, 200 fixed, 12 already fixed and 2 skipped. Both skips lie outside the sections: owner decision 145's record and this response's sizing, the record already corrected and the response corrected here (ST-N6), and the front matter's X6 row (T4-11). The 2026-11-05 close-out build fixed both in the assembler data.
- **Major re-check.** Ten independent checkers re-checked the panel's ten majors (peer/MAJOR-CHECK.json): 3 resolved (SC-N1, SL-N2, AU-N1) and 7 partial. They raised 49 further issues, 9 of them major.
- **Cross-section check.** Six checkers looked for issues that round 3's concurrent edits left between sections (peer/XS-ISSUES.json) and found 86, 20 of them major.
- **Round 4.** It fixed those 135 issues (peer/R4-OUTCOMES.json): 343 section items, 276 fixed and 67 already fixed.
- **Final re-check.** The seven partial majors were checked again against the sections as round 4 left them. OT-N1, OT-N2 and RT-N1 are resolved, with minor leftovers; SL-N1, WR-N1, ST-N1 and AU-N2 stayed partial until owner decisions 146-149 and rounds 5 and 6 fixed them (section 6.8).
- **The build.** The DESIGN.md built after round 4 (SHA-256 `164456b9…`, 14,510 lines) was assembled from the sections then, and its validation passed; section 1's build follows round 6 (section 6.8).
- **What no reviewer has re-checked.** Round 4's minor fixes were checked by the build validation but not each by an independent reviewer. That validation checks ids, links, superseded options, open questions and decision citations, not whether a fix closes its issue. The same holds for:
  - round 3's minor fixes, whose only second reading was the cross-section check, which looked for issues the concurrent edits left, not at each fix in turn;
  - 11 of the 29 major issues round 4 fixed, which lie outside the seven majors re-checked: the code-only recovery anchor (seven, under WR-N9), the escrow index's migration group (two, under OT-N3), the extension release that stage 2 waits for (T3-21) and removals during a path-epoch copy (SL-N2).

  Sections 6.1 and 6.2 mark these items *fixed*, not *resolved*, and reviewers re-check them at the gates named there.

### 6.8 Rounds 5 and 6 (2026-11-05)

Owner decisions 146-149 (section 2.4) decided the four majors the final re-check left partial. Section 6.2 names each one's mechanism.
- **Round 5** applied the decisions in the eleven sections that own those mechanisms (peer/R5-OUTCOMES.json): 21 items, 20 fixed and 1 already fixed, §7.9's retain row, which owner decision 147 keeps.
- **Round 6** aligned the sections that round 5's notes left disagreeing (peer/ROUND6-FIXES.json, with its outcomes in the round's workflow journal): 10 items in 8 sections, 2 of them major, all fixed. With them:
  - the single-device recovery deadlock that round 5's §5 edit found is fixed: a device the restored code admits anchors from the config ReaderWrap a config writer stages, in §7.9's restored order, before it commits, wraps, seals or signs (§5.6, §10.5, §10.8, KF2; §22.7), and §2.8's EX5 cites that order;
  - closure uploads count per eraser, within each eraser's own 60 a minute, and the network's erasure rate only queues ERASE and CLOSURE pushes as P1 (§11.12, §15.7, §20.7; FS-47);
  - tombstones are collected only in collect windows a head CAS opens (`EvsCollect`), and fold and copy writes are cancelled 15 s after their head read (§11.7's stale and collect rows; §2.8 evs-3, evs-11; FI-15, FS-58);
  - D-OPS-20: both clusters run an in-house MinIO build whose cancels reach every drive and keep locks until drive operations answer, so a cancelled write lands within a measured lag or never, and before any later request on its key (§19.6's cancel row; §19.17).
- **Not re-checked.** These fixes passed the build validation (section 1), but no independent reviewer has re-checked each of them. That validation checks ids, links, superseded options, open questions and decision citations, not whether a fix closes its issue. Sections 6.1 and 6.2 therefore mark them *fixed*, not *resolved*, for a reviewer's re-check at M2-in.
- **Residuals the round notes name:**
  - *One config writer* (§10.15's risk row): the restored code's device anchors only once a config writer gives it its ReaderWrap (KF2). If M, the network's only config writer, loses every device after a void no device re-signed, none remains, and the device never anchors. M's devices raise `recovery_rebind` at the void, and any of them can run `ur keychain recovery-rotate` (§5.9).
  - *Closure bytes per network* (§20.15's risk row): with no network-wide closure-upload rate, a network's daily closure bytes are bounded only by its admissions times the allowance, about 312 GiB for a Team's 5,000.
  - *Marker cost* (§11.20's risk row): each marker adds ~12.5-14 KiB of drive writes, and a collect window can hold a re-creating fold for up to 30 s; §22.8's fold row measures both before D-TEST-11's 43 KiB gate.
  - *Versions after collection* (§11.7's versions row): owner decision 148's "versions never restart" holds while a marker stands. Once it is collected, at folded_through ≥ r + 64, a path may restart at 1, since no push based before the removal can then commit.
  - *A stalled drive* (§19.17's risk row): under D-OPS-20's build, a drive operation stalled past the 30 s drive timeout can still land late.
  - *D-OPS-20 not yet in §11 and §22* (§19's round-6 note; by M2-in): §22.9's file-cluster row names final-upstream MinIO, not D-OPS-20's build, and lacks the slowed-remote-drive case and "before any later request on its key"; §11.13's store needs and §11.3 lack D-OPS-20's measured lag, ordering and remote-drive fact; and §11.7's collect row keeps 100 ms margins, which two clocks each up to 50 ms off (§19.6) plus the cancel's lag can exceed.
  - *The metadata list* (§2's round-6 note): 15 of §2.8's 90 rows, evs-3 and evs-11 among them, are not strict YAML, since plain scalars contain ": "; this predates rounds 5 and 6.

## 7. What the second round answered, and what reviewers re-check next

The final panel (section 6.4) answered the questions this section put to the reviewers. In brief, by group:

1. **The commit protocol under the storage redesign.**
   - I-EVS-1 to I-EVS-7 hold with batch records, places and window entries, and Resolve never drops a committed record.
   - Receipts keep I-EVS-5's fence and recheck, and nothing re-creates a `--now` shred.
   - The fence before a refusal closes the delayed-first-attempt case. It rests on clocks agreeing within 100 ms (SC-N3), and it aborts every concurrent attempt (SC-N4).
   - The `idx/` folds do not keep the path-level CAS exact (ST-N1). The path-epoch copy mishandles directories a fold moved (SL-N2), and the seal skips 5g's directory rules (SC-N2).
2. **Authority and keys.**
   - The authorization log, the gate predicate, `gen/` claims, the generation-0 self-join, the recovery window and owner decision 144's leaves rule hold.
   - Open: the replay window against retention (AU-N4), site-loss adoption with one uploading member (AU-N6) and the one-hop cascade (AU-N2, AU-N3).
   - The witness contract does not deliver §2.8's chain of witnesses (WR-N1, WR-N2).
3. **Runtime.**
   - The approval ledger and the gate's `approval_use` row, the reap predicate, the `sidecar_http` split, `protocol/bridge`'s contents and owner decision 142's rule hold.
   - Open: restore attribution without a pre-edit hash (section 6.1), and MCP's evs tools reaching the `secret` kind (RT-N1).
4. **Edges, mail and network.** All seven checks hold. New: the relation's public inputs (EM-N4), CAA flattening (EM-N3) and a static ShareKey (AU-N7).
5. **Operations and gates.**
   - D-PHASE-7, §23.6 against §22.10, and the pending-migration tag hold.
   - Open: the durability table's second-host row (SL-N4), rows newer than the main dump (OT-N1), the dns zone after a Postgres restore (OT-N2) and the escrow evidence's milestone (OT-N3).
6. **Where we did not take your proposal.** Every reason holds but one. For T1-09 the lookup cost suffices, but our catalog reason does not hold.
7. **The disclosed residuals.** They are accurate where stated, except:
   - the split witness (WR-N1, WR-N3);
   - a never-read path's pre-pin version, which a HeadCheck does not confirm (SC-N7, OT-N8);
   - DATA mode's copy, which gives no size (T4-02);
   - single-site DNS, missing from §23.4's M7 row (T4-23);
   - harness evidence in untainted runs and the sandbox operator, both missing from §2.18 (T3-05, T3-23).
8. **The storage tier.** The full review found the tier as owner decisions 136-140 and 145 require, and its figures reproduce from the model. ST-N1 is its one major.

**Next.** Please re-check each open item of sections 6.1 and 6.2 at the gate it names, against the revised DESIGN.md.
