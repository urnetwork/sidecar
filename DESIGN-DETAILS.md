# Design details

Detailed designs for the hard algorithmic problems that remained in DESIGN.md on 2026-11-09. Each problem's brief is in `.stack/design-problems.md`. The owner directed a fifth agent, on Fable at max effort, to work them out here, and directed that implementation in each problem's area wait until its section is complete.

Where a complete section and DESIGN.md differ, the section governs the tasks it names, until a design-records track folds it into `design/source/`. Each section ends with its proposed DESIGN.md text and its owner questions.

Status values: `pending`, `in progress`, `complete (date)`, or `complete pending owner question <file>` (built on the stated recommendation).

| # | Problem | Tasks held | Status |
|---|---|---|---|
| 1 | Search index merges, roll-ups and the journal (§11.14) | 7 | pending |
| 2 | Storage consistency under stalled writes: segment GC and the MinIO settle rules (§11.13, §19.6) | 4 | complete (2026-11-10) |
| 3 | Zero-knowledge proofs of TLS delivery for outbound mail (smtpproof; §14.5) | 5 | pending |
| 4 | Forwarding in the apps' VPN component: key, verification and size (owner decision 197) | 40 | complete (2026-11-10) |
| 5 | Authorization-log verdicts across folds (§7.9) | 13 | complete (2026-11-09) |
| 6 | MLS group key management (§10) | 13 | complete (2026-11-10) |
| 7 | Remote search across designated indexers (§11.14, §18.4) | 3 | pending |
| 8 | Git and evs in both directions | 3 | complete (2026-11-10) |
| 9 | Client path epochs and re-tokenizing | 3 | complete (2026-11-10) |
| 10 | DROP lists a phone can check (§11.6, §11.7, §11.9) | 5 | pending |
| 11 | Canonical text extraction and exact body sizes for search | 2 | complete (2026-11-10) |
| 12 | Bridge compiler and NAT engine (§17) | 4 | pending |
| 13 | Smaller scheduling problems: closure pacing, quota leases, socket registration | 4 | complete (2026-11-10) |

## 1. Search index merges, roll-ups and the journal (§11.14)

Status: pending

Tasks held until complete: SEARCH-M10-10, SEARCH-M10-11, SEARCH-M10-13, SEARCH-M10-14, SEARCH-M10-15, SEARCH-M10-35, TEST-M10-02.

## 2. Storage consistency under stalled writes: segment GC and the MinIO settle rules (§11.13, §19.6)

Status: complete (2026-11-10)

Tasks held until complete: EVSB-M10-01, EVSB-M10-02, EVSB-M2-12, EVSB-M2-17.

Models: `sidecar/sidecartest/model/details/Settle.tla` (the store's settle rules) and `EvsGc.tla` (segment GC beside evacuation), their configurations and `run-settle.sh` beside them. Questions filed: `.stack/questions/details-2-orphan-age.md`, `.stack/questions/details-2-conditional-delete.md`, `.stack/questions/details-2-list-whole.md`, `.stack/questions/details-2-drop-job-new-ref.md`. Questions this section answers, each on the option 2.9 names: `evs-models-gc-unfenced-new-ref`, `evs-models-settle-stalled-deletes`, `evs1-m2-12-first-commit-gc-fence`, `evsb-m2-11-pending-record-no-head`.

### 2.1 The problem

§19.6's settle row (D-OPS-20) promises that a PUT or DELETE "takes effect before every later request on its key or never", and everything evs deletes rests on it: a removal marker's collection, the versionless purge, a drop job, evacuation and orphan GC all issue unconditional DELETEs. The row also admits what makes that hard. A drive commit is a check and then a rename, and one that stalls after its check lands whenever its host wakes. A write that reached N/2 + 1 drives releases its key while its other commits are still on their way. A write that fell short is reverted drive by drive, some of those reverts after its key was released.

A *stalled write* in this section is a write some of whose drive commits passed their check and have not renamed. It has one of three fates. If it already holds a write quorum it is acknowledged, and the stalled commits only add copies later. If it cannot reach one and enough drives may still hold it, it holds its key, and every request on the key waits, then fails 503, until its hosts answer. Otherwise it is released as failed and its late commits land on an unheld key. evs sees the second fate as a head it can neither read nor write, and the model `EvsCommit.tla` keeps it as `heldBy`.

TLC finds the design wrong in two places, and working them out found three more.

**A. Segment GC does not fence a ref that has no head yet (question evs-models-gc-unfenced-new-ref).** §11.13's orphans row deletes a segment no committed push introduced once it is 25 h old, after raising "the fence of each ref of the repo whose head was written before that LastModified + 24 h", waiting the store's deadline and checking the repo's commits again. A fence is a head CAS, so a ref with no head gets none. The trace, on `EvsCommit.tla` at depth 18 and on this section's `EvsGcWritten-NewRef` in 15 states:

1. A client uploads segment s1 and signs a push that creates a path on a ref never written. Its receipt is fresh.
2. evs reads the ref's head, which is absent, checks the push (5h passes: the receipt is under 24 h old), writes its batch record and issues step 7, the head created If-None-Match.
3. The PUT's drive commits stall after their checks. It holds the head's key.
4. 25 h pass. GC lists s1, finds no committed push introducing it, and lists the repo's refs to fence. The new ref has no head, so GC sends that key nothing and never learns it is held.
5. GC waits the deadline and checks the repo's commits again: none.
6. The stalled PUT lands. The head now exists, at version 1, naming s1.
7. GC deletes s1. A committed head names a deleted segment: I-EVS-1 and I-EVS-5 are broken.

On a ref with a head the same push is safe, because GC's fence CAS on that head waits behind the held key and then changes the ETag. A process paused between its last clock check and its send (FS-59's schedule) reaches the same end on a new ref without any stalled drive.

The landed evacuation meets the same wall from the other side (question evsb-m2-11-pending-record-no-head). §11.13 resolves a pending batch record by raising its ref's fence, and `HeadStore.RaiseFence` answers `ErrEvsHeadAbsent` for a ref with no head, so every push that created a ref, passed step 5 and died before step 7 leaves a record evacuation can never settle. Its minute directory stays on NVMe, and after 1,440 such minutes a run stops looking further.

**B. Two DELETEs on one key break FI-30 (question evs-models-settle-stalled-deletes).** Rule (3) releases a failed write "once the drives that may still hold it ... number under N/2, so that write can never be read". That is true of a PUT, whose version is its own. Every DELETE leaves a drive in the same state, the key absent, and a read counts absent drives together whichever DELETE left them.

*B1, stalled DELETE commits add up* (`SettleWritten-Sum`, 12 states, 4 drives on 2 hosts, read at 2). DELETE w1 takes the key, its commit on drive 1 passes its check and stalls, its deadline passes, and w1 is released as failed with one drive possibly holding it. Drive 1's commit lands: the key is absent there. DELETE w2 does the same on drive 2. Host 2 goes down. Drives 1 and 2 answer not found, a read quorum, so a GET answers 404 for a key whose acknowledged state is the initial PUT. At 8 drives two DELETEs stalling three commits each leave six drives without the key and no host need fail. Rule (3) bounds each write's stalled commits and never their sum.

*B2, a late revert undoes a later DELETE* (`SettleWritten-Revert`, 16 states at 4 drives; found at 8 drives by simulation in the question). DELETE w1 fails as above and is released; its stalled commit lands on drive 1. DELETE w2 takes the key and counts drive 1, which lacks the key, as committed, as rule (2)'s "or its absence" reads and the build does. w1's coordinator, reverting "as it lands", restores drive 1: the check passes, because the drive still lacks the key, which is all a DELETE leaves to compare. w2 commits on drives 2 and 3 and is acknowledged at three drives counting drive 1. The drives hold `initial, absent, absent, initial`: a read quorum holds the value w2's acknowledged DELETE removed.

**C. A PUT's last commit undoes a later DELETE, found here** (`SettleWritten-Straggler`, 21 states, one PUT and one DELETE, no fault). PUT w1 creates the key: three of four drives commit, w1 is acknowledged and its key released, as rule (3) says ("a later commit of it only adds a copy"), with drive 4's commit still on its way, inside its deadline. DELETE w2 takes the key. It removes the key from drives 1 and 2 and counts drive 4, which lacks it. w1's commit now reaches drive 4. Rule (2) asks whether the drive still holds what w1's coordinator read there, which was the key's absence, and it does. The commit lands. w2 is acknowledged. The drives hold `absent, absent, w1, w1`, and a GET returns the object w2 deleted. This needs a DELETE served within the deadline of a PUT on the same key, which evs's own margins keep apart (a fold's write deadline ends before a marker's collection may delete; a purge waits 60 s), but FI-30 is stated for the store, and §10.6's and later callers' margins are not evs's. It is the same defect as B2 seen from the other side: rule (2) compares the version a drive holds, and absence is not a version. A drive that lacked the key, gained it and lost it again cannot be told from one nothing touched. A heal's copy fails the same way (`SettleWritten-Heal`, 22 states): a heal reads a drive that lacks the key, a DELETE counts that drive, and the heal's commit then lands the deleted object there, which FI-30's "no heal undoes" forbids.

**D. A second GC run deletes a segment uploaded again, found here** (`EvsGcWritten-Zombie`, 18 states, no stalled write). Orphan GC's DELETE is unconditional, as every DELETE is (§11.3: MinIO ignores a condition on one), and a segment's key is its content's hash. Two GC runs decide on one orphan: taskworker's once key keeps one run per shard, but a worker paused past its claim's 5 min lease wakes beside its successor. The first run deletes the segment. Its uploader, resuming a push days later, stores the same bytes again, gets a fresh receipt and commits. The second run, still holding its decision, issues its DELETE, which takes the new object. Neither fences nor checks help, since the second run's were all made before the re-upload. The drop job is protected from this by its lease and the deadlines on its DELETEs (§11.13's clock row), marker collection by its window; orphan GC has neither.

**E. A LIST that drops a key, found here.** §11.13 deletes on what a LIST shows: a segment no pidx/ entry introduces, a container no entry names. This section adds one more, the oldest batch a LIST of pb/ returns. MinIO asks the drives of a set that are online and lists a key only if half of those hold it (`cmd/metacache-set.go:728-733`), so with three of a set's eight drives offline it can leave out a batch or an entry that five drives took and that a read would still return. No model here holds this one; it is a count of drives, in 2.2.2.

The requirement: no committed head ever names a deleted segment; FI-30 holds for every mix of PUTs and DELETEs; and the settle rules stay correct with stalled drive commits, reverts as they land, DELETEs and new refs together, inside the cost and latency §11.13 and §19.6 budget.

### 2.2 The design

#### 2.2.1 The principle

Two rules, one for each side.

**In the store, a drive commit is a compare-and-swap on what the drive has applied, and nothing of a failed DELETE outlives its key's release.** Rule (2) gains a *stamp*: each drive counts the commits it applies, and a commit lands only if none was applied to its key on that drive since its coordinator read it under the key's lock. Absence then has an identity, so a commit from before a DELETE can no longer match the absence that DELETE left (C), and a DELETE may go on counting a drive that lacks the key. Rule (3) holds a failed DELETE's key until every drive commit of it has answered and each that landed is reverted, so no two failed DELETEs' leavings are ever visible together (B1) and no revert of one runs beside a later write (B2). A PUT keeps rule (3) as written, since its version is its own.

**In evs, GC waits for evacuation instead of fencing.** Every head write that can make a segment reachable is preceded by a batch record (§11.8's steps 6 and 7), and evacuation settles every record before its batch goes: a committed one is kept behind a pidx/ entry that names the segments it introduced, and a pending one has its ref fenced and is then dead. So the oldest batch left on a cluster is a *horizon*: every push whose record is older has committed, visibly, or never will. GC deletes a segment only once the horizon has passed the last minute a receipt for it could have been checked in. It raises no fence, reads no batch and never needs the name of a ref. The one fence left is evacuation's, per pending record, and for a ref with no head that fence is a placeholder head, which §11.8's first row already has for refusals. GC's DELETE names the object it listed, so a run that wakes late deletes nothing else (D).

The push route does not change. §11.8's first commit to a new ref stays If-None-Match, with no write before step 4.

#### 2.2.2 The store: rules (2) and (3), a DELETE that names its object, and a LIST that is whole

Rules (1), (4), (5) and (6) stand as §19.6 has them. All of this is in the `minio` fork.

**Rule (2), the stamp.** Each drive's host keeps, per drive and in memory:

```text
boot       16 random hex digits, drawn when the process opens the drive
counter    how many commits the process has applied on the drive, over all keys
remembered per key, the counter's value n at the last commit applied to it, kept StampKeep (2 min) past
           that commit; keyed by the 64-bit hash the stash already uses, so two keys may share an entry,
           which can only make a commit stale
stamp      boot:n for a remembered key, boot:0 for any other
```

```text
SettleRead(key) -> version@stamp          a new storage call, under no lock (reads take none, as today)
  version   what the key's xl.meta holds, as settleVersionOf names it today, or absent, or corrupt
  stamp     read after the version

a drive commit carrying {id, expect, deadline}: a data or metadata rename, a DELETE, a heal, a revert
  arrive    stale if the id is fenced                                                        (as today)
  lock      the drive's lock on the key, held to the end; stale at the deadline              (as today)
  check     stale unless SettleRead(key) = expect; a revert checks instead that the drive still
            holds its write: the version's settle id, or the DELETE's stash with the key as that
            DELETE left it                                                                   (as today)
  gate      stale at or past the deadline, while the clock is unsure, or if the id was
            fenced meanwhile                                                                 (as today)
  mark      counter += 1; remember {key, counter, now + StampKeep}                           (new)
  rename    apply. A DELETE of a key the drive lacks applies nothing, leaves its empty stash,
            counts as committed and is marked like any other
  unlock
```

A commit that answers stale changes nothing and marks nothing. A coordinator fixes a commit's deadline before it issues the `SettleRead` whose answer the commit carries, and no deadline is more than `RequestDeadlineMax` (1 min) past its request's arrival or `CommitDeadline` (40 s) past its start, so every commit's deadline is at most 1 min after its read. The build refuses to start unless `StampKeep` is at least twice the larger of the two.

The stamp is compared whole, as a string, so a restart, which draws a new boot, makes every commit read before it stale: rule (5) already keeps the old process's commits off the drive. A drive's version and stamp are read without the drive's lock, so a read beside a commit can pair the old version with the new stamp or the new with the old. Such a pair is the drive's state once that commit ends, or never is while the commit's entry is remembered, since the counter only rises; and 2.3 shows a forgotten entry can only be matched by a commit past its deadline.

**Rule (3), a DELETE.** The coordinator's states for one write; the `released` and `after` rows are where a DELETE now differs from a PUT:

```text
taken      it holds the key's lock; rule (1) refused it if its deadline had passed
read       SettleRead on every drive; a drive that does not answer is sent no commit; under N/2 + 1
           answers the write fails with nothing sent
committing each drive is pending, then committed, clear (stale) or still pending (an answer that does
           not say)
success    N/2 + 1 committed: acknowledged, and the key released. Its other commits go on and only add
           copies; each is refused by its stamp once any later commit was applied on its drive
settling   the deadline passed, or every drive answered, short of N/2 + 1: probe each drive not clear,
           which fences the id there, and revert each committed drive
released   a PUT: once no answering drive holds it and the drives that may still hold it (pending,
           running or committed on a host that does not answer) number under N/2
           a DELETE: once no drive may still hold it: none pending, running or committed
           until then requests on the key wait, then fail 503
after      a PUT: a commit that lands later is reverted as it lands, by its own version
           a DELETE: nothing is left to land or to revert
```

A settler (rule (4)) follows the same states. `settleMayRevert` is unchanged: a settler does not revert a write that may have been acknowledged. A drive replaced since its commit went out answers by its new disk and is clear, as today.

Why a PUT keeps its bound and a DELETE does not: a failed PUT's stalled commits each leave a version no read quorum holds, and reverting one restores what its own drive held; they cannot add up with another write's. A failed DELETE's stalled commits leave the one state every DELETE leaves, and a reader counts them together.

**A DELETE that names its object.** A DELETE may carry `x-ur-if-unmodified-ms: T`, the LastModified, in Unix ms, of the object its caller means:

```text
after the key's lock and rule (1), on the object info the handler already reads under the lock
  no object                       as today: nothing is sent to a drive, and the caller gets 204
  ModTime, in ms, >= T + 1,000    412, and nothing is sent to a drive
  else                            the DELETE, by rules (2) and (3)
```

The second of slack lets a caller pass a time it read from a HEAD, whose Last-Modified has whole seconds. `BlobCluster.Delete` sends it for a context that `sidecar.WithBlobUnmodified(ctx, lastModified)` made, as `WithBlobDeadline` carries a deadline today, and answers `ErrBlobPrecondition` on the 412. A DELETE without the header is unconditional, as it is today.

**A LIST that is whole.** MinIO asks the drives of a set that are online and lists a key that at least half of those asked hold (`cmd/metacache-set.go:728-733`). An acknowledged key is on N/2 + 1 drives, so a LIST names every key that can still be read while no drive of the set is offline, or at most two are and none is healing; past that it can drop a key whose shards are only out of reach. The horizon is a LIST, GC's and the container rows' reads of pidx/ are LISTs, and a reader's negative pidx/ lookup is one. The build therefore answers a LIST 503 whenever a set it must read is past that line, and asks every online drive whatever `list_quorum` is set to. That line is §19.6's at_risk state on a metadata set (a third drive lost, or a drive lost during a heal) and one host down on a segment set.

**Settings.** `StampKeep` (`_MINIO_SETTLE_STAMP_KEEP`, 2 min) joins `cmd/settle-settings.go`. Nothing else is new, and `RequestDeadlineMax`, `CommitDeadline` and `StashKeepMinAge` keep their values.

**One build.** A commit's expectation changes form, from `version` to `version@boot:n`, and a drive compares it whole, so a coordinator and a drive of different builds agree on nothing and every commit between them is stale: a mixed cluster fails closed. D-OPS-20's build has run on no cluster, so no upgrade across this change is owed; §19.6's "per build, upgrade and cluster" gate covers later ones.

#### 2.2.3 evs: the record, and the fence of a ref with no head

Three rules. The first two are already what the landed code does and become rules a test holds; the third is a change.

```text
record   an attempt appends its batch record and awaits its write before it issues step 7, and checks
         step 7's 5 s window after that write, against step 4's reads (pushAttempt.commit: step6, then
         withinStepSeven, then HeadStore.Commit). So the record of any attempt whose head write can land
         was acknowledged within 5 s of a 5h check that passed
minute   a batch opens only while the process's clock is sure (§19.6's clocks row), under the UTC minute
         it opens in. So a batch's key names a minute no later than 50 ms past the time each of its
         records joined it
fence    HeadStore.RaiseFence on a ref with no head creates a placeholder head If-None-Match: version 0,
         no window, kind or mode, fence 1, fence_ms its writer's clock. On 412 it reads the head again and
         goes on as after any 412: a commit that landed first is found committed by Resolve, a refusal's
         placeholder is fenced by If-Match
```

The `record` rule binds every route that writes a head naming new segments: a push, a seal, and EVSB-M2-20's re-seed, whose reseed record goes before its head write. The `minute` rule is a change of one check: `BatchWriter` opens a batch only while `ClockCheck.Sure()`, and `Append` answers `ErrEvsClockUnsure` otherwise, which its caller answers 503 as it does any unwritten batch. Push routes already refuse before step 4 on an unsure clock; this closes the attempt that was past step 4 when the clock turned.

A placeholder a fence made is the placeholder a refusal makes (§11.8's first row), with fence_ms set: reads, listings, `GET .../refs` and the lease route treat it as absent; the ref's first commit replaces it by If-Match and keeps its fence count and any refusal records; it stays, as a tombstone head does. A creating attempt that held the absent head fails its If-None-Match, reads the placeholder, finds its fence_ms later than its own arrival and ends 503 unknown, as §11.8's fence row says of any head. An attempt that arrives later reads the placeholder and commits on it by If-Match.

Evacuation's resolve row then needs no case for a ref with no head:

```text
per record, on its ref's head read from the cluster (a held key waits, then 503: the minute waits)
  committed at this place    keep: container, then pidx/ entry, then the batch         (as today)
  committed at another       drop                                                      (as today)
  dead                       drop, with the new slots its record lists                 (as today)
  pending                    RaiseFence, which now always has a head to raise or makes one; resolve again
                             on the head it wrote: dead, by the fence_ms just set, or committed
```

`ResolvePush` needs no change: on a placeholder its first dead rule cannot hold (the version is 0) and its second does (the statement's 35 min are long past at 25 h, and fence_ms is now).

#### 2.2.4 Segment GC by the evacuation horizon

```text
AdoptionBound   24 h + 2 min: the last minute directory that can hold a record adopting a segment starts no
                later than its LastModified + AdoptionBound (2.3's arithmetic)
horizon H       of a metadata cluster, from one LIST of pb/ with limit 1 at time t by the lister's checked
                clock: the start of the minute the oldest batch key names, or t - 25 h, evacuation's floor,
                if that is earlier or no batch is left. Every batch whose minute starts before H has been
                evacuated
orphan          a seg/ object of a repo whose LastModified + AdoptionBound is at or before the H of the
                repo's metadata cluster and whose id no pidx/ entry of the repo lists as introduced
```

Orphan GC runs inside the nightly pass (EVSB-M2-12), per shard job and repo, as P2 work that spends no NVMe budget (its DELETEs are on the HDDs):

```text
shard job, before any LIST of pidx/:
  0  no GC in this job while ClockCheck.Sure() is false, nor for a repo while SettlePassed() is false on the
     segment cluster or on the repo's metadata cluster (§19.6: every host answering, on the build that passed)
  1  H[c] for each metadata cluster c the shard's repos are placed on: one LIST(pb/, limit 1) each, as above

per repo R on metadata cluster c, after the pass's LISTs of seg/<R>/ and pidx/<R>/ (both issued after step 1):
  2  proceed only while repo/<R> shows active or deleted and no hold covers R (each cached at most 5 s)
  3  C := the seg/ objects with H[c] - Window <= LastModified + AdoptionBound <= H[c]; none: done
  4  I := the introduced ids of every pidx/<R>/ entry whose own LastModified is at or after
          min over C of LastModified, less 1 h; each entry by one GET. A 404 on a listed entry (a pack
          replaced its parcel): LIST pidx/<R>/<its ref>/ again and read what was not read, once.
          Over PidxReadCount (4,096) entries: delete nothing for R in this run and alarm
          gc_orphan_index_bound
  5  for each s in C not in I, oldest first, at most DeleteCount (1,024) a repo a run and DeleteRate
     (10 a second) a segment cluster, paused while that cluster's drive operations pass 50% of its measured
     capacity ({nvb_<cluster>}, as a drop job's are):
       step 2's two reads again; a hold or another state ends R's run
       DELETE seg/<R>/<s> with x-ur-if-unmodified-ms: its listed LastModified
         204                       deleted
         412                       the id was uploaded again: a new object, judged on a later night
         503 held, or unknown      left for a later night; never counted as deleted
```

`Window` is 7 d: the pass keeps no cursor (EVSB-M2-12), so each night judges the segments whose bound the horizon passed within the last 7 d, a segment about seven times, and a pass that did not run for longer than that is followed by one run with `Window` set to the gap. `DeleteCount`, `DeleteRate`, `Window` and `PidxReadCount` are `OrphanGcSettings`.

What GC no longer does: it raises no fence, waits no deadline, makes no second check and reads no batch. What it newly needs is `SettlePassed`, which §19.6 already asks of every other job whose DELETE leans on the settle rules: GC's DELETE now leans on rule (3) and on the condition it carries, and its horizon on a LIST that names every acknowledged batch, which 2.2.2's last rule makes the store's promise. Step 1 before step 4 is the one order that matters (twin `GcReadsIndexFirst`): an entry written before a batch's deletion is seen by any LIST issued after an H that the deletion moved.

A kind-5 segment that evacuation writes to seg/ from a batch (EVSB-M10-02's staged decision) is introduced by its record, whose pidx/ entry lists it, and is written in the run that writes that entry; it is a candidate 49 h later at the earliest and is found in I. An uploaded kind-5 segment whose push never committed is an orphan like any other.

#### 2.2.5 Uncommitted path maps

§11.6's map row sends "a map uncommitted 25 h after its upload" to the orphan rule. A PATH_EPOCH push adopts a map only while every part is under 24 h old at its check (5e), so the map's bound is its oldest part's LastModified + AdoptionBound. In the same job, for each `pmap/<R>/<ref>/<p>/<map>/` whose bound is at or before H[c]: read the ref's head from the cluster (after step 1; a held key leaves the map for a later night); if the head's current path epoch is below p, DELETE each part with `x-ur-if-unmodified-ms` its listed LastModified. A map at or below the head's current epoch is left to §11.6's "once p or a newer epoch commits" rule, which knows the committed map. The argument is 2.3's for a segment, with the ref's own head in place of the pidx/ entries: every PATH_EPOCH attempt that could adopt the map has a record behind the horizon, so it committed, and the head read after H shows an epoch at or past p, or it is dead.

#### 2.2.6 What a caller sees

```text
caller                      a held key (503, ErrBlobHeld)                a DELETE's unknown outcome
push, seal, lease           503 {outcome: unknown} once step 7 was       n/a
                            issued, else 503; the client retries
                            (as today)
fold, copy                  the write is retried by the next fold or     n/a
                            the copy's next pass (as today)
evacuation                  the record's minute waits (as today)         the batch is listed again next run
                                                                         and its records resolve as before
marker collection           the marker stays for a later window          the marker is read again in a later
                                                                         window; a 404 is done
versionless purge, sweep    the candidate is left to the sweep, then     the sweep HEADs it again
                            to the next run's sweep
orphan GC                   left for a later night                       left for a later night
drop job                    the id stays unanswered; the cursor does     the id stays unanswered
                            not pass it
a reader of a batch         as a 404 on the batch: the record is         n/a
record                      looked up through pidx/ (RecordLocator)
```

The last row is a change: a batch whose DELETE failed with a commit stalled on a silent host is held, and every record in it was moved before that DELETE was issued (I-EVS-7), so `RecordLocator` treats `ErrBlobHeld` on a pb/ key as it treats a 404: it looks the record up through pidx/, and answers the 503 only if no entry holds it.

### 2.3 Invariants and why they hold

```text
store (Settle.tla)
NoStaleQuorum,       FI-30's first and third clauses: a read returns only the state the store decided, and no
ReadsSeeCurrent      earlier write, revert or heal undoes it
                     why: a write is acknowledged with N/2 + 1 drives holding its state. A drive among them
                     changes afterwards only by a commit that passes rule (2) there, so one whose coordinator
                     read the drive after the acknowledged commit landed on it: never an older write's last
                     commit, whose stamp is spent, and never an older write's revert, which needs the drive
                     still to hold that write. A later PUT leaves its own version there, and its revert puts
                     back what it replaced; a later DELETE leaves absence, acknowledged or reverted before
                     its key is released; a heal copies the state then readable. So an older version, or an
                     older absence, can stand only on the at most N/2 - 1 drives outside that quorum, under a
                     read quorum
LateWritesNeverRead  a PUT released as failed is never read, whatever of it still lands (rule (3), unchanged)
RefusedNeverLands    nothing the store refused past its deadline reaches a drive (rule (1), unchanged)
FailedDeleteSettled  once a failed DELETE's key is released, no drive commit of it can land or be reverted
                     why: rule (3) releases it only with no drive pending, running or committed
HeldKeyReleased      every held key is released once its stalled commits answer and its hosts return (liveness)
                     why: a stalled commit answers committed or stale; a committed one is reverted, by the
                     coordinator or the settler; a write a settler cannot revert, because it may have been
                     acknowledged, is found to hold a write quorum once its hosts answer

evs (EvsGc.tla)
ClosureHolds         I-EVS-1 for segments: no committed head ever names a deleted segment
GcSafe               I-EVS-5: no segment becomes reachable after GC decided to delete it
RecordsKept          I-EVS-2 and I-EVS-7: a committed push's record is in its batch or in a container a pidx/
                     entry names
HeadsRise            a placeholder head exists only with its fence raised
RecordsLeave         every record old enough to evacuate leaves its batch (liveness): none stays pending for
                     want of a head to fence
```

**Why GC is safe.** Let s be a seg/ object with LastModified T, and suppose GC found T + AdoptionBound at or before H, where H came from a LIST of pb/ at time t, and then found s in no pidx/ entry.

1. An attempt can commit a version naming s as new only with a receipt for this object. A fresh receipt's `upload_ms` is evs's clock before the PUT began and a re-upload's is the LastModified itself, so `upload_ms` is at most T + 100 ms. Its last 5h check passed under 24 h after `upload_ms` by evs's clock.
2. By the `record` rule its record was acknowledged within 5 s after such a check, and by the `minute` rule the batch's key names a minute that began no later than 50 ms past that. So the batch was acknowledged before T + 24 h + 5.3 s and its minute began before then too, which is 114.7 s before T + AdoptionBound.
3. H is at most t - 25 h, so the LIST ran a day after T + AdoptionBound, when every such batch had long been acknowledged and so was listed unless deleted (2.2.2's LIST rule). The oldest batch listed begins at or after H. So every such batch has been deleted. A batch whose PUT stalled and lands later holds only records whose attempts were told their batch was not written and issued nothing.
4. Evacuation deletes a batch only after it settled each record (I-EVS-7): kept, with its container and its pidx/ entry, which lists s, written first; dropped as a second copy of a push that another record commits, to which 2 and 3 apply as well; or dead.
5. Dead is final. A pending record's ref is fenced, by a head CAS or, for a ref with no head, by the placeholder's creation. A stalled head write holds the key, so the fence waits behind it and finds it landed, the record then resolving committed, or reverted. Every other attempt of the push that reached evs before the fence holds the head as it was and fails its write, or reads the fenced head and ends (§11.8's fence row); one that arrives later fails 5b, 25 h after its statement's time.
6. So from t on, every push that adopts this object is committed behind a pidx/ entry listing s, or will never commit. GC's LIST and GETs of pidx/ are issued after t, and an entry is never deleted before the entry that replaces it is written (§11.13's index row). Not finding s there, no version names this object and none ever will.
7. A version that names s later carries a receipt from a later upload, which made a new object, since If-None-Match stored it after the old one was gone. Its LastModified is days past T, and a DELETE carrying `x-ur-if-unmodified-ms: T` answers 412 for it. So however late, and however many times, a GC run issues its DELETE, it removes the object it judged or nothing.
8. A version that names s without a receipt took it from a committed version step 4 read (5h), so s was already introduced, and 6 found it.

The margins of step 2 are `EvsGc.tla`'s ASSUME, in ms: 24 h for the receipt, 100 for its stamp against LastModified, 5,000 for step 7's window, 50 for each of two clocks and 60,000 for a key's minute. They sum to 54.8 s less than AdoptionBound.

**Why a forgotten stamp is safe.** A commit c carries the stamp boot:n it read at time r, and its deadline is at most r + 1 min. Suppose a commit c' was applied to the key on that drive after r. While c' is remembered the drive's stamp carries a higher count than any c could have read, so c is stale. Once c' is forgotten, StampKeep after it was applied, the stamp reads boot:0, which equals c's only if c read boot:0; but that is at least 2 min after r, a minute past c's deadline, and the gate refuses c on the drive's clock, which §19.6 holds within 50 ms. After a restart the boot differs and every earlier read is stale.

**The models.** `Settle.tla` is `StoreSettle.tla`, which the data lane owns and this section leaves untouched, with the two store rules. A stamp is the fact `fresh[w][d]`: no commit was applied on drive d since write w's coordinator read it; every commit, revert that changes a drive and heal clears it for every write. A failed DELETE's release needs no drive that may still hold it. A heal's commit is read under the key and may reach its drive after the key's release, as a write's may, where `StoreSettle.tla` checks it in the step that reads. It adds `MaxPuts` and `MaxDeletes`, which fix a run's mix of writes, `Still`, which holds heal or cancels out of a run, the invariant `FailedDeleteSettled`, and the action constraint `NoLateWriteCommits`, which one configuration uses to leave heal's the only late commit. Twin `Written` turns both rules off, which is §19.6 as DESIGN.md states it; `NoStamp` and `DeleteReleasesEarly` turn off one each; `StoreSettle.tla`'s seven twins are kept.

`EvsGc.tla` is new and small where `EvsCommit.tla` is whole: one repo's segments (uploaded, deleted and uploaded again), a ref with a head and a ref with none, pushes that take a receipt, check it, write a batch record and issue a head write that lands, fails, stalls holding its key or is sent late by a paused process, the evacuator (resolve, fence, placeholder, keep, drop, killed at any step), one or two GC runs whose DELETE may itself stall, and time in ticks, where a receipt lasts 2 and a minute is evacuated 3 ticks old. Its twin `Written` is §11.13's orphans row as DESIGN.md states it.

Runs, TLC at the owner's jar (master d8fb231), each bounded so it finishes; breadth-first over every reachable state at its bounds unless it says simulation. `run-settle.sh` stops a run whose state directory passes 8 GB and deletes each run's state directory as it ends; the largest here used 1.7 GB on disk.

```text
configuration                          what it runs
                                       result                                        distinct states depth        time
Settle.tla, the design (Twin none); 4 drives on 2 hosts, read at 2 and written at 3, unless a row says otherwise
Settle                                 2 writes of either kind, 1 coordinator, a reader; commits stall, deadlines pass,
                                       reverts land
                                       pass, every invariant                                 426,576    28         5 s
Settle-Hosts                           the same with a host failure
                                       pass, every invariant                               1,818,910    29        51 s
Settle-Heal                            a host failure, and heal, whose commit may land after the key's release
                                       pass, every invariant                               5,150,490    35  1 min 38 s
Settle-Cancel                          a host failure and cancels
                                       pass, every invariant                               7,065,302    30        54 s
Settle-Settler                         2 coordinators, a host failure and a coordinator crash, which the settler settles
                                       pass, every invariant                              19,774,204    30  2 min 47 s
Settle-Three                           3 writes: one PUT and two DELETEs
                                       pass, every invariant                              14,569,638    38  8 min 59 s
Settle-Three-Puts                      3 writes: two PUTs and one DELETE
                                       pass, every invariant                              51,072,375    41 23 min 47 s
Settle-Live                            HeldKeyReleased under weak fairness: two DELETEs
                                       pass, the property                                    263,990    29        46 s
Settle-Live-Hosts                      HeldKeyReleased: one write, a host failure and a coordinator crash
                                       pass, the property                                     66,824    19         3 s
Settle-Six                             6 drives on 3 hosts, read at 3 and written at 4, 2 writes, 2 coordinators, a host failure,
                                       a crash, heal and cancels; simulation, 50,000 traces a worker of up to 70 steps, seed 3
                                       pass, every invariant on those traces         35,000,002 generated         7 min 1 s
Settle-Wide                            §22.8's bounds: 8 drives at EC:4 on 4 hosts, 3 writes, 2 coordinators, 2 host failures,
                                       a crash, heal and cancels; simulation, 100,000 traces a worker of up to 60 steps, seed 1
                                       pass, every invariant on those traces         60,000,002 generated       29 min 56 s
Settle-Eight                           8 drives, 2 writes, 2 coordinators, a host failure, a crash, heal and cancels;
                                       simulation, 50,000 traces a worker of up to 90 steps, seed 2
                                       pass, every invariant on those traces         45,000,002 generated       13 min 59 s
Settle.tla, §19.6 as written (Twin Written)
SettleWritten-Sum                      two DELETEs and a host failure (B1)
                                       NoStaleQuorum violated, a trace of 12 states           85,302    13         1 s
SettleWritten-Revert                   two DELETEs, no host failure (B2)
                                       NoStaleQuorum violated, a trace of 16 states          107,318    16         2 s
SettleWritten-Straggler                one PUT and one DELETE (C)
                                       NoStaleQuorum violated, a trace of 21 states          339,404    21         6 s
SettleWritten-Heal                     one PUT, one DELETE and heal, no write's commit late (C, by a heal)
                                       NoStaleQuorum violated, a trace of 22 states          156,441    22         3 s
SettleWritten-Eight                    8 drives, two DELETEs, no host failure or crash; simulation, seed 7 (B2 at §22.8's drives)
                                       NoStaleQuorum violated, a trace of 35 states  23,107 generated               0 s
Settle.tla, one rule of the design broken
SettleTwin-NoStamp                     rule (2) compares the version alone; one PUT and one DELETE
                                       NoStaleQuorum violated, a trace of 21 states          200,790    23         3 s
SettleTwin-DeleteReleasesEarly         a failed DELETE released as a PUT is; a host failure
                                       NoStaleQuorum violated, a trace of 12 states          175,694    12         2 s
SettleTwin-DeleteReleasesEarly-Settled the same, held to the rule itself
                                       FailedDeleteSettled violated, a trace of 5 states             427     6         0 s
SettleTwin-ReleaseOnCancel             StoreSettle.tla's twins, on this model, DELETEs on:
                                       NoStaleQuorum violated, a trace of 7 states             4,434     7         0 s
SettleTwin-NoDeadlineCheck             LateWritesNeverRead violated, a trace of 6 states             470     6         0 s
SettleTwin-NoVersionCheck              NoStaleQuorum violated, a trace of 21 states          493,754    21        10 s
SettleTwin-RevertBelowQuorumOnly       LateWritesNeverRead violated, a trace of 6 states           1,054     7         0 s
SettleTwin-SettlerRevertsUnseen        NoStaleQuorum violated, a trace of 14 states          996,078    14        14 s
SettleTwin-HealMinority                NoStaleQuorum violated, a trace of 9 states            10,138    10         0 s
SettleTwin-NoDriveLock                 NoStaleQuorum violated, a trace of 16 states          395,171    17         7 s
EvsGc.tla, the design (Twin none); one segment id, a ref with a head and a ref with none, a receipt lasting 2 ticks,
a minute evacuated 3 ticks old
EvsGc                                  GC, stalled writes, a new ref and DELETEs in one run: 2 pushes, 1 GC run, 2 uploads of
                                       the id, 2 stalled writes (a head write or GC's DELETE), a paused attempt, a killed
                                       evacuation, 7 ticks
                                       pass, every invariant                              15,088,610    44  1 min 40 s
EvsGc-Zombie                           2 GC runs alive at once, the id uploaded again between them; 1 stalled write, 1 pause,
                                       6 ticks
                                       pass, every invariant                               2,552,184    40        32 s
EvsGc-Long                             10 ticks: uploaded, orphaned, deleted, uploaded again, adopted and evacuated; 1 stalled
                                       write
                                       pass, every invariant                               4,192,137    44        49 s
EvsGc-Live                             RecordsLeave under weak fairness: 1 push, a stalled write, a pause, a killed evacuation
                                       pass, the property                                     36,644    30         4 s
EvsGc.tla, §11.13's orphans row as written (Twin Written)
EvsGcWritten-NewRef                    one push, one stalled write (A)
                                       ClosureHolds violated, a trace of 15 states             2,770    17         0 s
EvsGcWritten-Zombie                    one push, two GC runs, two uploads, no stalled write (D)
                                       ClosureHolds violated, a trace of 18 states            30,887    20         0 s
EvsGc.tla, one rule of the design broken
EvsGcTwin-GcIgnoresHorizon             GC goes by the object's age alone
                                       ClosureHolds violated, a trace of 14 states             3,766    14         0 s
EvsGcTwin-GcReadsIndexFirst            GC reads pidx/ before the horizon
                                       ClosureHolds violated, a trace of 19 states             3,161    20         0 s
EvsGcTwin-UnconditionalDelete          GC's DELETE takes whatever holds the key; two GC runs
                                       ClosureHolds violated, a trace of 21 states            19,990    21         0 s
EvsGcTwin-FenceSkipsAbsentHead         a pending record on a ref with no head is called dead, unfenced
                                       RecordsKept violated, a trace of 14 states              3,410    15         0 s
EvsGcTwin-PendingStaysOnAbsentHead     such a record is left where it is, as the landed draft leaves it (liveness)
                                       RecordsLeave violated, a trace of 20 states            24,632    30         2 s
EvsGcTwin-RecordAfterPut               a head write issued with no record before it
                                       RecordsKept violated, a trace of 7 states                 155     9         0 s
EvsGcTwin-DeleteBeforeIndex            a kept record's batch deleted before its pidx/ entry
                                       RecordsKept violated, a trace of 13 states              1,337    14         0 s
EvsGcTwin-AdoptsOldReceipt             5h takes a receipt of any age
                                       ClosureHolds violated, a trace of 15 states             3,239    15         0 s
```

Every design run passes, and every written and twin run ends on the one invariant or property its configuration names. The design runs used ten workers (`EvsGc`'s four, eight) and the written and twin runs six. With more than one worker a trace is the first one TLC's workers met, which in some runs is a few states longer than the shortest, and a distinct-state count moves a little from run to run; a twin's count is what TLC had explored when it met the violation. The times are from a machine four build lanes were loading, at a load average near 50 on 14 cores, and are several times what the same runs took when it was idle.

What the runs cover. The breadth-first runs of `Settle.tla` take every interleaving, at 4 drives, of two writes of either kind and of three writes in both mixes that matter (a create with a DELETE on either side of it, and two DELETEs beside a PUT), with a commit stalled at any drive, every deadline, a host failure, a coordinator crash settled by another host, cancels, and a heal whose commit lands late. Larger sets do not finish: EVS1-M2-02 stopped `StoreSettle.tla` at §22.8's 8 drives and 3 writes at 412.6 M states and depth 12, and this model was stopped at 6 drives with one PUT and one DELETE at 19 M states and depth 19, and at 4 drives with three writes of any kind at 38 M states and depth 22, with no violation in either. `Settle-Six`, `Settle-Wide` and `Settle-Eight` therefore sample 6 and 8 drives, and show only that the traces they drew kept every invariant; a simulation's count is TLC's own figure for the traces it was asked for. `EvsGc` is the run problem 2's brief asks for, GC with stalled writes, a new ref and DELETEs together: both refs take pushes, either push's head write may stall holding its key or come late from a paused process, GC's own DELETE may stall holding the segment's key, the segment is uploaded again after it goes, and evacuation is killed mid-record.

The findings of 2.1 each appear against the text as written and are gone in the design: A in `EvsGcWritten-NewRef`, B1 in `SettleWritten-Sum`, B2 in `SettleWritten-Revert` and, at 8 drives, `SettleWritten-Eight`, C in `SettleWritten-Straggler` and `SettleWritten-Heal`, D in `EvsGcWritten-Zombie`. Each rule of the design has a twin that fails without it: the stamp (`NoStamp`), the DELETE's release (`DeleteReleasesEarly`, on FI-30 and on the rule itself), the horizon (`GcIgnoresHorizon`), its order before the pidx/ read (`GcReadsIndexFirst`), the DELETE that names its object (`UnconditionalDelete`), the placeholder fence (`FenceSkipsAbsentHead` for safety, `PendingStaysOnAbsentHead` for the record that never leaves), the record before the head write (`RecordAfterPut`), the entry before the batch's deletion (`DeleteBeforeIndex`) and the receipt's age (`AdoptsOldReceipt`).

Neither model holds the LIST rule or the stamp's 2 min: a LIST is whole in both, and a stamp is never forgotten. The first is 2.2.2's count of drives and the second is the arithmetic above.

### 2.4 Cost

Against §11.13's write budget (a create ~9 KiB a drive, an overwrite ~14 KiB, a delete ~3.5 KiB; 43 KiB a push), §11.8's three round trips a push and §19.6's "one drive or host failing holds a key at most for a revert's round trip":

```text
the push path                 no change: no write before step 4, no extra head CAS, no wait. The first commit
                              to a new ref stays one If-None-Match. (Option 2 of the GC question would cost one
                              more head create, ~9 KiB a drive and one round trip of 13-27 ms, per new ref.)
orphan GC's fences            none, where §11.13 as written raises one head overwrite, ~14 KiB a drive, on every
                              ref of the repo idle since the 24 h mark, each time a night finds an orphan there:
                              a repo of 1,000 refs with one orphan a night cost ~14 MiB a drive a night
orphan GC's waits             none: no store deadline to wait out and no second check
evacuation                    one head create, ~9 KiB a drive, the first time a pending record is found on a ref
                              with no head; later ones on that ref are the overwrite §11.13 already prices. Such a
                              record needs a creating push that passed step 5 and died before step 7
an orphan's life              49 h to 51 h after its upload until GC may delete it, where §11.13 says 25 h; with
                              the nightly pass, 49-75 h where §2.8's evs-4 says 25-49 h. An orphan counts in its
                              network's stored bytes meanwhile (§20.7), a day longer than before
GC's reads, a night           one LIST of pb/ with limit 1 per metadata cluster and shard job; per repo with a
                              candidate, one GET for each pidx/ entry written in the last ~9 d (Window, the bound and
                              a day's lag): at §11.13's ~3 pidx/ writes a second in year one, ~2.3 M GETs a night,
                              ~27 a second averaged, 1.1% of year one's ~2,400 GET/s; ~270 a second in year two,
                              1.3% of ~21,000. Reads are not metered (§11.13)
GC's DELETEs                  one per orphan, on the HDDs, which spend no NVMe budget; at most 10 a second a
                              segment cluster, as a drop job's; the header costs no read, since the handler reads the
                              object's info under the lock for every DELETE already
the store, each write         SettleRead in place of the ReadXL the build issues today: the same one read a drive,
                              a smaller answer. One map write at each commit
the store's memory            an entry of ~50 B per key committed in the last 2 min, per drive: at year two's
                              ~5,700 writes a second, ~690,000 entries, ~35 MB a metadata drive; nothing on disk
a LIST                        unchanged while it is whole. 503 where upstream would answer with what it had: three
                              drives of a set offline, or one offline during a heal
a failed DELETE's key         held until its last drive commit answered and was reverted, where rule (3) as
                              written released it at under N/2. With every host answering that is the same one
                              probe and one revert round. It is longer only when a DELETE falls short of N/2 + 1
                              while a commit of it is stalled on a host that does not answer: a host frozen
                              mid-commit beside a second fault, or beside a deadline that passed mid-fan-out,
                              which only marker collection's and a drop job's DELETEs carry that tightly. One
                              frozen host alone leaves 6 of 8 drives to commit, and the DELETE succeeds
a DELETE's latency            unchanged on success
```

No budget in §11.13 or §19.6 is passed, and the push path's latency and bytes do not move. The cost that grows is an orphan's residence, by a day, which is the owner's to accept (2.9).

### 2.5 Failure modes and recovery

```text
evacuation falls behind or     the horizon is its cluster's, so one minute that waits stops it for every repo
stops (a P0 storm, a batch     placed there: GC deletes nothing and orphans accumulate, harmlessly, counted in
of an unknown format, a        their networks' stored bytes. §19.8's oldest-batch age
repo it cannot judge)          (urnetwork_evs_evacuation_oldest_batch_seconds) already alarms past 26 h. GC resumes
                               by itself as evacuation drains; a gap over Window needs one pass with Window widened
a host of either cluster       SettlePassed reads false within 60 s and GC stops for the repos placed there, as
down, or on another build      every job whose DELETE leans on the settle rules does (§19.6)
a set past the line a LIST     its LISTs answer 503: the nightly pass and evacuation stop on that cluster, and a
can be whole at (2.2.2)        reader's pidx/ lookup that is not cached fails 503, until a drive returns or a heal
                               ends. Nothing is decided on a LIST that could have dropped a key. One host of a
                               metadata cluster down is inside the line; one host of the segment cluster down is
                               past it, so the nightly LIST of seg/ waits for that host
a head write stalls on a ref   the head's key is held. Evacuation's read or fence of it waits, then fails 503, the
whose record is due            record's minute waits, and the horizon with it. §19.8 pages a key held over 1 min;
                               §19.10's held-key row brings the host back or replaces its drives, the write lands
                               or is reverted, and the next run settles the record
a first commit stalls on a     the same: evacuation's placeholder creation waits behind the held key. If the write
new ref                        lands, the creation gets 412 and the record resolves committed; if it is reverted,
                               the placeholder lands and the record is dead
a creating push dies between   25 h later evacuation writes the fenced placeholder and drops the record with its
its record and step 7          slots. The ref lists as absent. A later push to that name commits on the
                               placeholder by If-Match
GC killed anywhere             nothing to undo: it holds no fence, lease or cursor. The next night judges again
a GC run paused past its       its DELETEs name the objects it listed: each removes that object or answers 412
claim, waking beside another
GC's DELETE falls short of     its key is held until the stalled commits answer; an upload of that id waits, then
its quorum with a commit       fails 503, and its client retries. The DELETE took effect or was reverted whole;
stalled                        the next night lists what is there
a clock unsure                 taskworker: no fence and no GC. evs: no push past step 4, and no batch opens. A
                               MinIO host: no request carrying a deadline and no drive commit (§19.6, unchanged)
a drive host restarts          its stamps are gone and its boot is new, so every commit read before the restart
                               answers stale there: a write in flight loses that drive's copy, or reads the drive
                               again and commits (StaleRetries), and heal catches the drive up. Rule (5) and the
                               settler are unchanged
two builds in one cluster      every commit between them is stale: writes fail 503 where a write quorum of one
                               build is not reachable, and nothing lands wrongly
a pidx/ entry GC listed is     a pack replaced a parcel: GC lists that ref's entries again, once, and reads the
gone                           pack's. Still missing: it deletes nothing for the repo that night
a hold placed while GC runs    step 5 reads hold/ again before each DELETE and stops the repo
```

### 2.6 The test plan

**Unit tests in the fork** (`minio/cmd/settle-*_test.go`, with the test hooks the build already has: `commit-arrived`, `commit-checked`, `revert-checked`, `key-release`):

```text
the stamp      a commit that read a drive before another commit was applied there answers stale, for a PUT
               over a version, a PUT over absence and a DELETE; a DELETE of a key the drive lacks marks it; a
               stale commit marks nothing; SettleRead pairs a version with its stamp, and a read beside a
               commit held at commit-checked yields a pair that passes later only if that commit changed
               nothing; a heal's commit read before a DELETE passed its drive is stale; an entry is forgotten
               at StampKeep on the fake clock, and a commit read before it, sent after, is refused by its
               deadline; a new process's boot makes every earlier read stale; a StampKeep under twice the
               longest deadline refuses to start
rule (3)       a DELETE short of its quorum with one commit held at commit-checked keeps its key, and
               releases it once that commit lands and is reverted; nothing of it is reverted after
               key-release; a PUT in the same schedule releases under a read quorum as today; an orphaned
               DELETE stays held until its silent host answers
the four       B1, B2, C and C by a heal, of 2.1, as schedules on a 4-drive set, each ending with a GET of the
traces         acknowledged state from every host
conditional    x-ur-if-unmodified-ms deletes the object it names, answers 412 for one stored at least a second
DELETE         later, 204 for a missing key, and tolerates a time truncated to the second
LIST           answered with two drives of a set offline, and with two healing and none offline; 503 with
               three offline, and with one offline beside one healing; every online drive asked under any
               list_quorum
```

**Unit tests in sidecar:**

```text
evsservice/head_test.go        RaiseFence on a ref with no head creates the placeholder with fence_ms; on a
                               ref created meanwhile (412) it fences the head it finds; a fenced placeholder
                               lists as absent and takes a first commit by If-Match; a creating attempt that
                               held the absent head ends 503 unknown at it
evsservice/evacuate_test.go    a pending record on a ref with no head is fenced by placeholder and dropped (in
                               place of TestEvacuationLeavesAPendingRecordOnARefWithNoHead); a held head on a new
                               ref leaves the minute waiting; a first commit that landed before the fence keeps
                               its record
evsservice/batch_test.go       a batch opens only on a sure clock; a key's minute is never past its records'
evsservice/push_test.go        no head write is issued when the batch write fails or is unknown; step 7's window
                               is checked after the record's write
evsservice/gc_orphans_test.go  the horizon from an empty pb/, from its oldest key and from a key younger than
                               t - 1 min; nothing deleted before the horizon; a segment a pidx/ entry lists kept;
                               the horizon read before the pidx/ LIST, with a barrier between (evs.gc.horizon,
                               evs.gc.index, evs.gc.delete, each .before and .after); a segment uploaded again
                               between the LIST and the DELETE answers 412 and stays; a held key is left; a hold
                               and a repo not active or deleted stop the repo; an unsure clock deletes nothing;
                               the index bound; a replaced pidx/ entry listed again; a map above the head's epoch
                               deleted past its bound and one at or below it left
evsservice/locate_test.go      a held batch key reads through pidx/
sidecartest/blobsuite          Delete with WithBlobUnmodified: takes the object, refuses a newer one, nil for a
                               missing key; on the fake and, in EVSB-M2-17, on T3
```

**Schedule rows.** FS-59 is rewritten, FS-8 and FS-114 gain clauses; no row is added, so D-TEST-10's count stands. 2.8 has their text.

```text
FS-59    the paused push on an idle ref, now ended by evacuation's fence at 49 h and GC's DELETE after it; a
         first commit to a new ref held at the store past GC, landing and keeping its segment, and reverting
         and losing it; a creating push killed after its record; two GC runs with the segment uploaded again
         between them; the twin whose push commits
FS-8     the fake clock passes 26 h, 2 d and 3 d: evacuation has dropped every dead record and its slots at
         26 h, and GC every orphan segment at 3 d
FS-114   two DELETEs of one key, each with a commit held past its deadline; a create whose last commit is
         held at commit-arrived across an acknowledged DELETE; a failed DELETE's key held until its last
         commit answers; a DELETE naming an older object; a drive host restarted between a read and its commit;
         a LIST with three drives of a set stopped
```

**Models.** This section's `Settle.tla` and `EvsGc.tla` stay under `details/` as its record. The two models §22.8 names take the same rules, in the tasks that own them:

```text
StoreSettle.tla   EVS1-M2-02's owner adds fresh and rule (3)'s DELETE bound as Settle.tla has them, the
                  invariant FailedDeleteSettled and the twins NoStamp and DeleteReleasesEarly; its twins
                  drop Quiet=deletes; StoreSettle.cfg's bounds follow Settle's configurations, since §22.8's
                  8 drives and 3 writes do not finish (EVS1-M2-02's report: 412.6 M states at depth 12)
EvsCommit.tla     its GC process becomes the horizon rule: GcMark needs every batch record at or before the
                  segment's bound gone and reads Introduced from pidx; GcFence, GcRefs and GcCheck go;
                  GcDelete names the object; MapReclaim follows; twins GcNoFence and GcNoSecondCheck give way
                  to GcIgnoresHorizon and GcReadsIndexFirst, and FenceSkipsAbsentHead joins; the quiet part
                  newrefstall goes, so the stalled first commit runs in every GC configuration
run-tlc.sh,       the twin tables and mutants.yml follow: GcSafe names GcIgnoresHorizon and GcReadsIndexFirst,
mutants.yml,      ClosureHolds adds FenceSkipsAbsentHead, NoStaleQuorum adds NoStamp and DeleteReleasesEarly,
modelled.yml      FailedDeleteSettled names DeleteReleasesEarly; modelled.yml records the new runs
```

**Go twins.** The models' Go side is `sidecartest/model`'s tests: `modelled_test.go` holds `mutants.yml` to `run-tlc.sh`'s twin tables and each cfg's INVARIANT list, both ways, so the new invariant and twins must land in all three together, and `model_test.go`'s `TestStoreSettlePassesTlcAtItsBounds`, `TestStoreSettleMutantsFailTlc` and `TestStoreSettleLivenessHolds` then run the corrected model at bounds that finish; neither file changes. The store's Go side is the fake: `sidecartest/fake_blobs.go` keeps the settle rule for T2 and gains the DELETE that names its object (a 412 changes nothing) and a `Held` fault on a DELETE; `sidecartest.CheckBlobHistory`, FI-30's oracle over what clients saw, treats a 412 on a DELETE as no effect; `sidecartest/fault/fi30.go`'s comment on the fourth clause takes FI-30's new words.

### 2.7 Implementation notes, task by task

The held tasks need three pieces of landed code changed first. They are small, and each is a task of its own so the held ones can name it. They are numbered here after EVSB's last M2 task; the orchestrator may number them otherwise.

**New: EVSB-M2-22, the stamp and the DELETE rules in the fork** (minio; M; before EVSB-M2-17). In `cmd/settle-drive.go`: `settleDrive` gains `boot`, `counter` and the remembered entries, under `stateLock`, swept as `idFences` is; `settleRun` gains `mark()`, called wherever `settleHookCommitChecked` and `settleHookRevertChecked` fire, before the hook, and by every other run past its last gate, the ones that carry no expectation included (`xl-storage.go`'s metadata writes); `run.check` compares `Expect` with version@stamp. A new storage call `SettleRead(ctx, volume, path) (string, error)` beside `SettleProbe` (`storage-interface.go`, `storage-datatypes.go` and its generated code, `storage-rest-client.go`, `storage-rest-server.go`, `xl-storage-disk-id-check.go`, `internal/grid/handlers.go`, `naughty-disk_test.go`), which `settleReadVersions` calls in place of `ReadXL`; a drive that does not answer it is sent no commit. In `cmd/settle-write.go`: the release test in `run` becomes `tally.mayHold() < self.releaseBound()`, 1 for a write with `absentCommits` and `readQuorum` otherwise, and the file's header comment says so; `settleRenameData` and `settleDeleteVersion` take `settleCommitDeadline(ctx)` before `settleReadVersions`, as do heal (`erasure-healing.go:658`) and the dangling delete (`erasure-object.go:551`). In `cmd/settle-deadline.go`: the middleware reads `x-ur-if-unmodified-ms` into the context (`internal/http/headers.go` names it), and `erasureServerPools.DeleteObject` answers `PreConditionFailed` after `getPoolInfoExistingWithOpts` when the object it found has a ModTime at or past the value plus a second. `cmd/metacache-set.go`: `listPath` answers `InsufficientReadQuorum` when the set has three or more drives offline, or one offline beside one healing, and asks every online drive whatever `o.AskDisks` says. `cmd/settle-settings.go`: `StampKeep`, and the start-up check. `SIDECAR.md` says what changed. Tests: 2.6's fork list. Traps: mark after the last gate and before the rename, never before the check; a DELETE's revert check stays the stash's, since its key is held; the stamp is one string, compared whole.

**New: EVSB-M2-23, a DELETE that names its object, in the Blobs contract** (sidecar, server; S; before EVSB-M2-12). `sidecar.WithBlobUnmodified(ctx, lastModified)` in `host_blobs.go` beside `WithBlobDeadline`, and `BlobCluster.Delete`'s comment; server's MinIO client sends the header where it sends `x-ur-deadline-ms` (`server/file_cluster_transport.go`) and maps the 412 to `ErrBlobPrecondition`; the fake and `blobsuite` as 2.6 says.

**New: EVSB-M2-24, the fence of a ref with no head** (sidecar; S; before EVSB-M2-12). `evsservice/head.go`: `RaiseFence` builds the placeholder when the head is absent and `ErrEvsHeadAbsent` goes. `evsservice/evacuate_resolve.go`: `evacuateRun.resolve` loses its `head.Absent()` branch and the `evacuate_pending_no_head` alarm, and `fence` prices a create when the head is absent. `evsservice/batch.go`: `BatchWriter` takes a `ClockCheck` and opens a batch only while it is sure. `evsservice/locate.go`: `RecordLocator` takes `ErrBlobHeld` on a pb/ key as a 404. Tests: 2.6's head, evacuation, batch, push and locate rows. The push route's files (`push_step4.go`, `push_commit.go`) do not change; its two new tests hold the order it already has.

**EVSB-M2-12, the nightly pass.** Build as planned, with these changes. The shard job takes each metadata cluster's horizon first, before any LIST of pidx/, and hands it to orphan GC; `evsservice/nightly.go` owns that read (`OrphanHorizon(ctx, cluster) (time.Time, error)`: one `List(batchKeyPrefix, "", 1)`, the minute by `batchKeyMinute`, as evacuation reads it, the clock held to `ClockCheck`, an unsure clock an error). Every DELETE the pass issues for an object it listed (a superseded pack or parcel and its entries, an unnamed container after 25 h, a consumed deposit's segment) carries `WithBlobUnmodified` with the listed LastModified, and counts a 412 as "replaced", never as deleted; a held key or unknown outcome is left for the next night. The pass still calls EVSB-M2-13 and EVSB-M2-14. Nothing else of its plan entry moves.

**EVSB-M2-13, orphan GC** (not held by name, but it needs EVSB-M2-12 and is this section's subject). Build 2.2.4 and 2.2.5 in `evsservice/gc_orphans.go`, not its plan entry's four steps: no `RaiseFence`, no deadline wait, no second check, no batch read. It runs for a repo only while `SettlePassed()` holds on the segment cluster and on the repo's metadata cluster, and `ClockCheck.Sure()`. `OrphanGcSettings{AdoptionBound: 24 h + 2 min, Window: 7 d, DeleteCount: 1024, DeleteRate: 10, PidxReadCount: 4096}`, with `AdoptionBound` a floor no setting passes. Barriers `evs.gc.horizon`, `evs.gc.index`, `evs.gc.delete` replace `orphan_mark`, `orphan_fence`, `orphan_recheck` and `orphan_delete`. It exports, per segment cluster and with no network or repo label (D-OPS-8), `urnetwork_evs_orphan_deletes_total{outcome}` with outcome deleted, replaced, held or failed. Its Needs lose `HeadStore.RaiseFence` and gain EVSB-M2-23 and `EvsPidxEntry`'s introduced ids (EVSB-M2-10). Tests: 2.6's GC row, FS-59's GC clauses and FS-8's.

**EVSB-M2-17, the file-cluster suite and FS-114.** Needs EVSB-M2-22. Add 2.6's FS-114 clauses to the suite's cases, each with its barrier (the fork's hooks), and the conditional DELETE's three cases to the store suite. The suite reports, with the lag it already reports, how long a failed DELETE's key was held past its request's end. A build without EVSB-M2-22 fails the new cases, the DELETE naming an older object first, so `SettlePassed` is never recorded for one.

**EVSB-M10-01, the versionless purge.** No change of rule. Its DELETEs stay unconditional and without the header: a kind-5 segment is cited only by its own path's next version on its own ref (I-EVS-10), so no write on another head can make one reachable again, and FI-30, which the purge's 60 s allowance leans on, now holds for DELETEs (2.3). What it must handle: `ErrBlobHeld` and an unknown outcome leave the candidate to the sweep, never counted as deleted or reported as freed; `SettlePassed` false deletes nothing, as planned.

**EVSB-M10-02, staged decisions and the sweep.** The sweep already HEADs each candidate before it deletes one: it passes that HEAD's LastModified with `WithBlobUnmodified`, and counts a 412 as absent. A staged segment written to seg/ at evacuation is listed as introduced in its record's pidx/ entry, written in the same run before the batch's DELETE, which is what keeps orphan GC from it (2.2.4). Its two one-off passes (a hold's end, purge turned on from observe) delete with the header too. Held keys and unknown outcomes as for the purge.

**Order.** EVSB-M2-22, then EVSB-M2-23 and EVSB-M2-24 in either order, then EVSB-M2-12 with EVSB-M2-13, then EVSB-M2-17; EVSB-M10-01 and EVSB-M10-02 at M10 after all of them. The model changes of 2.6 run beside them.

**Other landed code this section touches by name:** `minio/cmd/settle-write.go`, `settle-drive.go`, `settle-deadline.go`, `settle-settings.go` and the storage interface (EVSB-M2-22); `sidecar/host_blobs.go`, `sidecartest/fake_blobs.go`, `blobsuite/suite.go`, `server/file_cluster_transport.go` (EVSB-M2-23); `sidecar/evsservice/head.go`, `evacuate_resolve.go`, `batch.go`, `locate.go` (EVSB-M2-24); `sidecartest/model/StoreSettle.tla`, `EvsCommit.tla`, `run-tlc.sh` and `mutants/mutants.yml` (their owners, 2.6). The evs commit path does not change.

### 2.8 Proposed DESIGN.md text

For a design-records track. Each item replaces the words it quotes and leaves the rest of its row.

**§11.3, the MinIO bullet.** For "A DELETE evaluates no precondition (...), so an If-Match sent with it is ignored.": "Upstream's DELETE evaluates no precondition (...), so an If-Match sent with it is ignored; §19.6's in-house build honors one condition of its own, `x-ur-if-unmodified-ms`, under the key's lock."

**§11.6, the map row.** For "and the nightly pass deletes a map uncommitted 25 h after its upload by 11.13's orphan rule": "and the nightly pass deletes a map above the head's epoch once 11.13's horizon has passed its oldest part's LastModified + 24 h + 2 min, each part by a DELETE naming its LastModified".

**§11.8.** In `EvsHead`: `written_ms`'s comment becomes "evs's clock at this head's write"; `fence_ms`'s "its writer's clock at the newest evacuation fence (outcomes)". The etag row: "only evacuation's fences also set fence_ms". Step 6 gains: "a batch opens only while the process's clock is sure (§19.6)". The fence row, for "evacuation and GC fences raise the head's fence and set fence_ms": "evacuation's fences raise the head's fence and set fence_ms (GC raises none, 11.13)"; for "a taskworker in that state raises no evacuation or GC fence and GC deletes nothing": "a taskworker in that state raises no fence and GC deletes nothing". The first row gains: "evacuation fences a ref with no head by creating the same placeholder with its fence raised and fence_ms set (11.13); a creating attempt then fails its If-None-Match and ends at the fence". The evacuate row, for "fencing a ref before it drops a pending record": "fencing a ref, one with no head by a placeholder head, before it drops a pending record". I-EVS-5:

```text
I-EVS-5  no segment becomes reachable after GC decided to delete it: a push, or a seal for its parts, adopts only
         an upload under 24 h old at its last check and writes its batch record before its head write; evacuation
         settles every record before its batch goes, a committed one behind a pidx/ entry that names its
         segments and a pending one by a fence on its ref, a ref with no head by a placeholder head; and GC
         deletes a segment only once no batch is left from before its LastModified + 24 h + 2 min, no pidx/
         entry read after that names it, and by a DELETE that names its LastModified
```

**§11.13.** The needs row, for "an unconditional Delete (11.3)": "a Delete, unconditional or naming its object's LastModified (§19.6)". The resolve row, for "pending -> raise the ref's fence (one head CAS), then Resolve again": "pending -> raise the ref's fence (one head CAS, or for a ref with no head one placeholder head created with its fence raised, 11.8's first row), then Resolve again". The orphans and why rows:

```text
orphans   the nightly pass first takes each metadata cluster's horizon, from one LIST of pb/: the start of the
          minute its oldest batch names, or 25 h before the LIST if that is earlier or none is left. It then
          LISTs each repo's seg/ prefix on the segment cluster, as it does for stored bytes, and its pidx/
          entries. A segment whose LastModified + 24 h + 2 min is at or before its repo's cluster's horizon and
          that no pidx/ entry lists as introduced is an orphan, and taskworker deletes it by a DELETE that
          names its LastModified (§19.6), at most 10 a second a segment cluster, on clusters whose build passed
          §19.6's settle cases. It raises no fence and reads no batch. An uncommitted path map above its ref's
          current epoch goes the same way, by its oldest part (11.6)
why       a push, or a seal for its parts, adopts a segment only with a receipt under 24 h old at its last check,
          writes its batch record within 5 s of that check and before its head write, in a minute that began no
          later; so every record that can adopt the segment is in a batch from before its LastModified + 24 h +
          2 min. Evacuation deletes a batch only once it settled each record: committed, behind a pidx/ entry
          naming the segment; or dead, its ref fenced after its statement lapsed, which ends every attempt
          however late its head write lands, a write that stalled holding the key included, since the fence
          waits behind it. Past the horizon nothing is pending, so a segment no entry names is named by no
          version and never will be; a later upload of the same bytes is a new object, which the DELETE's
          LastModified refuses
```

**§11.17.** D-EVS-25: "Orphans are found without the log: hourly evacuation resolves every batch record, which names every slot its push wrote, fencing a pending record's ref, one with no head by a placeholder head; and an unadopted segment or path map, found by the nightly LIST, is deleted only once evacuation's horizon has passed every batch that could adopt it. *Why:* an upload that never reached the log is otherwise invisible; a grace period cannot fence a late commit, and a fence cannot reach a ref that does not exist yet, but every commit leaves its record first." D-EVS-34: "... and GC deletes an unadopted segment only once every batch record that could adopt it has been evacuated, 49 h or more after its upload, by a DELETE that names the object. *Why:* markers cost three writes per segment."

**§19.6, the settle row.** Rule (2), for "the version the coordinator read from that drive under the lock, or its absence, and a deadline": "the version the coordinator read from that drive under the lock, or its absence, with the drive's stamp for the key (how many commits its process had applied when it last applied one to the key, kept in memory for 2 min, with a value drawn at the process's start), and a deadline fixed before that read"; for "applies it only while the drive still holds that version and its clock is before the deadline": "applies it only while the drive still holds that version and that stamp, so only if no commit was applied to the key there since the read, and its clock is before the deadline; a DELETE of a key the drive lacks counts as committed and moves the stamp". Rule (3), after "so that write can never be read and the version before it loses only the drives the write stalled on or could not revert": "; a DELETE, which leaves a drive in the one state every DELETE leaves, releases its key only once no drive may still hold it, each commit of it having answered and each that landed been reverted, and is never reverted after its release". For "a DELETE's .trash copy, which the trash sweep keeps while the key is held": QD-279's "a DELETE's stash". For "and a key waits longer only while a write lacking N/2 + 1 drives could still reach N/2 with a host among the drives holding it unreachable": "and a key waits longer only while a PUT lacking N/2 + 1 drives could still reach N/2, or a DELETE lacking them has a commit unanswered, with a host among those drives unreachable". After rule (6): "; a DELETE carrying x-ur-if-unmodified-ms is refused 412, under the key's lock, when the object it finds was stored a second or more after that time, which is how GC deletes only the object it listed (§11.13)". For "taskworker opens no collection window and v1's purge and drop jobs delete nothing": "taskworker opens no collection window, orphan GC deletes nothing and v1's purge and drop jobs delete nothing". The clocks row, for "taskworker raises no evacuation or GC fence and GC deletes nothing": "taskworker raises no evacuation fence and GC deletes nothing, evs opens no batch".

After the settle row, a row of its own: "list      a LIST is answered only when it is whole: the build asks every online drive of each set it reads and answers 503 when three or more of a set's drives are offline, or one is while another heals, since a key on N/2 + 1 drives can then fall under the half of the asked drives a listing needs; evacuation's horizon and every deletion decided on a LIST of pidx/ (§11.13) rest on it".

**§19.10, the held-key row, and §19.17's risk row.** For "releases once fewer than a read quorum of drives can hold the write": "releases once fewer than a read quorum of drives can hold a PUT, or none a DELETE".

**§19.13.** D-OPS-20, for "each drive commit applies only while its drive still holds the version the coordinator read under the lock; and a PUT or DELETE releases its key only once it holds a write quorum or can never reach a read quorum, reverting every drive that took it": "each drive commit applies only while no commit was applied to its key on its drive since the coordinator read it under the lock; a PUT releases its key only once it holds a write quorum or can never reach a read quorum, and a DELETE only once it holds a write quorum or no drive holds anything of it, each reverting every drive that took it; a DELETE may name the LastModified of the object it means". Its *Why* gains: "absence is not a version, so a drive's contents alone cannot tell a commit from before a DELETE from one after it, nor one failed DELETE's leavings from another's".

**§22.8.** The EvsCommit.tla row, for "segment GC (its 25 h mark, fence, deadline and second check)": "segment GC (the evacuation horizon, the pidx/ entries read after it and a DELETE that names its object), with a first commit to a ref with no head stalled across it". The StoreSettle.tla row, for "each drive's version and its own lock on the key": "each drive's version, its stamp and its own lock on the key"; for "TLC checks FI-30 with 3 writes, 2 coordinators and a reader": "TLC checks FI-30 with PUTs and DELETEs mixed, breadth-first at 4 drives on 2 hosts and at 6 on 3 with 2 and 3 writes, a coordinator crash and a host failure, and by simulation at 8 drives with 3 writes and 2 coordinators". FI-30's last clause: "a key is held only while a PUT lacking a write quorum could still reach a read quorum, or a DELETE lacking one has a drive commit yet to answer or be reverted (§19.6)".

```text
FS-59  §11    a segment uploaded; a push checked 23 h 59 min later pauses before its head CAS  FI-1,6      T2+T3  M2-out
              on an idle ref; at 25 h GC deletes nothing; at 49 h evacuation fences the ref
              for the push's record and drops it; the push fails its CAS and answers 503
              unknown, and its retry gets 409 SEGMENT_GONE; GC then deletes the segment by a
              DELETE naming its LastModified; again with a push that creates its ref and
              whose head write the store holds past 51 h: evacuation and GC wait, and the
              write landing keeps the segment while its revert lets the placeholder head
              fence the ref and GC delete; a creating push killed after its record: a fenced
              placeholder, the ref listing as absent, the record and its slots gone; two GC
              runs on one orphan with its bytes uploaded again and committed between their
              DELETEs: the second answers 412 and the segment stays; a re-upload of a 23.5 h
              old segment gets 409 SEGMENT_STALE; a forged or other-repo receipt is refused;
              the twin whose push commits before evacuation keeps the segment
```

FS-8, for "the fake clock passes 26 h and 2 d: GC and evacuation reclaim every orphan, a dead push's slots included": "the fake clock passes 26 h, 2 d and 3 d: evacuation has dropped every dead record and its slots at 26 h and GC has deleted every orphan segment at 3 d". FS-114, before "twin:": "two DELETEs of one key, each with a commit held past its deadline, on one host and with a host then down: the key is held until the held commits are released and reverted, and the object reads throughout and after; a create whose last drive commit is held before its check across an acknowledged DELETE of the key: released, it answers stale, and the key reads 404 through every host and after a full heal; a DELETE naming an older object's LastModified: 412, and the object stays; a drive host restarted between a write's read of it and its commit: stale;".

**§2.8.** evs-3's ttl, for "and a refused creation a placeholder head": "and a refused or fenced creation a placeholder head". evs-4's ttl, for "an upload no committed push adopted: deleted 25-49 h after its upload, once its repo's idle refs are fenced": "an upload no committed push adopted: deleted 49-75 h after its upload, once evacuation has settled every batch that could adopt it". Neither adds a value a server sees: the stamp lives in a storage host's memory, and `x-ur-if-unmodified-ms` is a time in a request header, as `x-ur-deadline-ms` is.

**Plan.** EVSB-M2-13's entry takes 2.7's words; EVSB-M2-22 to EVSB-M2-24 are added; EVSB-M2-17 needs EVSB-M2-22; EVSB-M2-12 needs EVSB-M2-23 and EVSB-M2-24.

### 2.9 Owner questions

This section is designed on the recommendation of each of the first three; the fourth is another problem's to build.

**How long an orphan lives (`details-2-orphan-age.md`).** D-EVS-34 and §2.8's evs-4 say an unadopted segment goes 25 h after its upload, 25-49 h with the nightly pass. Options: (1) the horizon rule of this section: 49-75 h, no GC fence, no change to the push path; (2) keep 25 h, with GC reading every batch of the last day each night to find the refs of pending records, fencing those and every idle ref of the repo, a ref with no head by a placeholder: a second read of a day's batches a night (tens of GB in year one), a head overwrite per idle ref per orphan night, and a second place that resolves records; (3) keep 25 h by having every creating push write a placeholder head before step 4 (the question's own option 2): one more head create and round trip per new ref, a change to the landed push route, and GC's fences as written. Recommendation: (1). An orphan is bytes its own uploader's network is charged for, a day longer; nothing else moves.

**A DELETE that names its object (`details-2-conditional-delete.md`).** §11.3 and the Blobs contract say a DELETE takes no condition. Options: (1) the fork honors `x-ur-if-unmodified-ms` under the key's lock, and GC, the nightly pass and the sweep send it: about thirty lines in the fork, one context helper, and D closed for any number of late or doubled runs; (2) GC HEADs each orphan just before its DELETE and bounds the DELETE's deadline to 2 s after: no store change, and D remains when a second run's DELETE, the re-upload and its commit all fall inside those 2 s; (3) a lease object per GC shard, as the drop job has: a new object family and §2.8 row, and a renewal write per checkpoint. Recommendation: (1).

**A LIST that is whole (`details-2-list-whole.md`).** MinIO lists a key that half of the drives it asked hold, so with three of a set's eight drives offline it can drop a batch that five drives took, and the horizon, like §11.13's existing rules that delete on a LIST of pidx/, would act on what is missing. Options: (1) the fork answers such a LIST 503 (2.2.2), a few lines, failing closed in §19.6's at_risk state and with a segment host down; (2) taskworker reads drive states from admin info and holds its deletes, which leaves readers' lookups and a 60 s window; (3) accept it. Recommendation: (1).

**The drop job and a ref with no head (`details-2-drop-job-new-ref.md`).** Found while checking who else deletes on the strength of a scan of the repo's refs. §11.13's drop job marks "over every ref of the repo" at a snapshot after each drop's fence. A push that creates its ref, validated before the DROP committed and citing a listed version through `reuse`, whose head write stalls past mark and verify (25 min after a `now` drop), lands on a head the scans never saw, naming a segment the job deleted. It is A again, at 25 min in place of 25 h. Options: (1) the job takes mark only once the horizon of 2.2.4 has passed each covered drop's commit by 2 min, so every record validated before the fence has been settled, which makes a `now` drop's deletion start about 25 h after it and leaves a 7-day drop as it is; (2) the job resolves pending batch records itself before mark; (3) accept it. Recommendation: (1). It belongs to problem 10's tasks (EVSB-M10-03 and EVSB-M10-04) and to `EvsCommit.tla`'s drop stories, which run only refs that have heads; this section builds nothing for it.

**Questions this section answers.** `evs-models-gc-unfenced-new-ref`: none of its options as stated; GC fences nothing, and the fence of a ref with no head is evacuation's placeholder (its option 1's write, made by evacuation). `evs1-m2-12-first-commit-gc-fence`: its option 1, the push route as it is. `evsb-m2-11-pending-record-no-head`: its option 1. `evs-models-settle-stalled-deletes`: its option 1, with the stamp for C, which it did not have; that option is the owner's too, since it changes FI-30's last clause and D-OPS-20's cost (2.4, 2.8). `evsb-m2-11-dead-record-shared-slot` is not answered here; its option 3 can take 2.2.4's horizon in place of reading batch-resident records, and a DELETE naming the slot's LastModified, when it is decided.

## 3. Zero-knowledge proofs of TLS delivery for outbound mail (smtpproof; §14.5)

Status: pending

Tasks held until complete: SMTP-M9-07, SMTP-M9-08, SMTP-M9-09, SMTP-M9-13, SMTP-M9-32.

## 4. Forwarding in the apps' VPN component: key, verification and size (owner decision 197)

Status: complete (2026-11-10)

Amended 2026-11-10 for the owner's answers: QD-621 (a narrowing statement the posture cannot check never makes the component pending; it keeps its last compiled state and alarms, where this section had it go pending at 10 min: 4.2.1, 4.2.2, 4.2.4, 4.2.5, 4.3 and `Fwd.tla`, 4.5, 4.6, 4.7's SDK-M8-17, BRIDGE-M8-05 and SDK-M8-15 entries, 4.8), QD-620 (its wording now follows QD-621: 4.2.4, 4.8) and QD-641 (the review-phase path for large networks in the Apple extensions is a storage-backed compile: 4.2.4, 4.4). 4.9 records every answer, QD-619 to QD-622.

Tasks held until complete: BRIDGE-M2-01, BRIDGE-M4-15, BRIDGE-M4-18, BRIDGE-M4-19, BRIDGE-M4-20, BRIDGE-M4-22, BRIDGE-M6-05, BRIDGE-M6-06, BRIDGE-M6-07, BRIDGE-M6-08, BRIDGE-M8-01, BRIDGE-M8-02, BRIDGE-M8-03, SDK-M10-01, SDK-M10-02, SDK-M10-03, SDK-M10-04, SDK-M10-05, SDK-M10-06, SDK-M3-01, SDK-M4-04, SDK-M4-05, SDK-M4-06, SDK-M4-08, SDK-M4-09, SDK-M6-02, SDK-M6-03, SDK-M8-01, SDK-M8-02, SDK-M8-03, SDK-M8-04, SDK-M8-05, SDK-M8-06, SDK-M8-07, SDK-M8-08, SDK-M8-10, SDK-M8-12, SDK-M8-14, SDK-M8-15, SDK-M9-01.

Model: `sidecar/sidecartest/model/details/Fwd.tla`, its configurations (`Fwd*.cfg`, `FwdTwin-*.cfg`) and `run-fwd.sh` beside it. Task list for the orchestrator: `.stack/plan/proposals/details-4-tasks.md`, which replaces `od-197-forwarding.md`. Questions filed: `.stack/questions/details-4-ios-forwarding-budget.md`, `details-4-ios-compile-memory.md`, `details-4-forwarding-reader-key-in-rows.md`, `details-4-compile-deadline.md`. Every size and heap figure below was measured on 2026-11-10 on the `sidecar` branch at 173e06d with Go 1.27.3 and Xcode's clang (iOS 16.0 minimum), unless it says estimate.

### 4.1 The problem

Owner decision 197 puts the device's IP and port forwarding, and nothing else of sidecar, in every app's VPN component (Apple's network extension on iOS and macOS, Android's VPN service, the Windows and Linux app services), always on, self-contained, with its own key, taking rule changes directly. The design-od197 track wrote that into DESIGN.md (§7.9's forwarding row and D-TEAM-33, §10.5, §17.8 to §17.10, §18.4, §18.6, §18.10, D-SDK-20, D-SDK-32): a forwarding Delegation that the sidecar S signs for keys the component generated, a `forward_only` forwarding client F, the component's own following of the log, its own compile, and its own signing of `WindowDelegation`s. Five things are left open, and four of them fail as written once measured.

**Size.** D-SDK-20 gave the keyless device role 1 MiB of growth in the iOS extension. `make size` today reads 37,789,784 B without the role and 39,017,184 B with it: 1,227,400 B added, over the limit before decision 197 adds anything (question sdk-m4-02-make-size-over, at 1,170,816 B the day before). §18.10 then proposes "at most 4 MiB" for the forwarding leg (Q-SDK-7), a figure nobody measured. Linking the root as it stands with §18.10's kept list (the follower, config verification, DelegationWrap unwrap and the ladder, evs head reads, the ACL state, the token path) and leaving the rest to the linker's dead-code removal adds 7,978,128 B unstripped and 7,123,048 B stripped. And §18.10's remedy, an allow-list of "the root's forwarding files", cannot be short: the root files those entry points need in order to compile are 269 of the leg's 428, because config, acl, evs, identity, record and rpc files name each other's types.

**Memory.** §18.10 proposes a Go heap of 4 MiB steady and 8 MiB while compiling, also unmeasured, inside a tunnel whose Go runtime measures 19.6 MiB connected and 26.0 to 27.4 MiB under provider load against a 28 MiB target and a 32 MiB soft limit (sdk/build/APPLE_EXTENSION_MEMORY_BUDGET.md). The landed loader holds a network's whole state decoded: with the rows of a 5,000-device team it takes 10.5 MB (4.4), so the compile §18.6 describes does not fit 8 MiB for the team §22.9's cell names, and a follower that keeps that state between compiles passes 4 MiB steady at about 1,900 devices.

**Rows.** A forwarding Delegation's row carries its X-Wing reader key, 1,216 B. One a device, in a team where two devices in three are apps, makes 5,000 devices' rows 5,898,574 B, over §8.8's 4 MiB, which every verifier refuses; the cap falls from about 13,400 devices to about 2,600 app devices. §10.15's risk row counted the wraps and missed the rows.

**Verification.** `BridgeState` is unsigned, and §18.6's `SetState(state)` takes it alone (question sdk-m4-01-state-proof). The od197 text names two verifiers in one process without saying which judges: `sidecar/device`'s posture, which checks bases and six statement kinds by rules of its own, and the root's follower. Section 5 requires that a verdict be judged once, by the rule table, and the landed posture lifts a Suspend on its own reading of an Unsuspend, which is an opening on a second judge. The overlay's kinds (§17.8) hold no `DelegationRevoke` and no supersession, so a revoked forwarding key stays admitted until the next compile, and nothing says what happens when no compile can run.

**The key's lifecycle as code.** §18.6's setup block names the steps but not their order, what survives a kill between them, where a second key set lives while the first still signs, what a host does between a supersession's entry and its compile, or what a rolled-back store may do.

The requirement: the VPN component enforces only what the authorization log's rule table judged, applies every revocation it can check at once and every other within a stated bound, never lowers enforcement on unsigned or stale input, and fits a size and memory budget that is measured, on every platform, with one implementation of every security-critical rule.

### 4.2 The design

#### 4.2.1 The principle

**One judge, two tiers: a denial is cheap and immediate, an opening comes only from a judged compile.** The VPN component is §7.9's rows-only verifier, the kind api and the gates are, with one thing more: a reader key that opens the config. It runs two tiers.

Tier 1 is the posture (`sidecar/device`, landed by SDK-M4-01), resident, streaming, built on `protocol/bridge`'s types alone. It verifies what it is given against the anchor, applies as an overlay of denials every revocation it can check, and opens nothing. Tier 2 is the compile (`Forwarder`, root), transient: it restores the shared rows-only `ConfigLog` from the store, which is the judge (section 5's `StartAtBase` and `Judge` for a rows-only verifier, the code api runs), opens sealed bodies and the head by the forwarding reader key, builds `AclState`, runs `CompileBridgeState` for S, hands tier 1 the state with the log run that vouches for it, and releases everything. Between compiles the component holds no network state in memory but the compiled tables.

Three consequences. The posture's own statement checks never decide what opens, so they need not equal the rule table's, only never pass what a signature does not cover. Every statement that could narrow reach and that the posture cannot apply starts a clock, and when no compile has resolved it in time the posture raises an alarm, again while it waits, and goes on enforcing its last compiled state: forwarding never drops for a statement the posture cannot check (4.2.5; QD-621). And the forwarding role is not a full reader: it does not re-compile a head to check a base's rows, which the app's sidecar role, a full reader, does whenever it runs and reports through the witness hint.

This answers sdk-m4-01-state-proof without a channel: the component fetches the log itself, so the base, its rows and the entries a state rests on are already in its own store, and `Posture.SetState(state, log)` keeps the argument SDK-M4-01 built, filled in process.

#### 4.2.2 Formats settled

Each is additive before M2's freeze (owner decision 194). Field numbers continue each message's.

```proto
// sidecar/protocol/bridge/auth.proto: declared here, not in config.proto, because sidecar/device reads a
// Delegation's field 7 by wire and may import only protocol/bridge
message ForwardScope {                 // config.proto: Delegation.forward = 7; set means a forwarding Delegation
  bytes forward_sidecar_id = 1;        // S, which must be the signer
  bytes host_client_id = 2;            // the device client D, in D's network; empty in any other
  bytes host_client_public_key = 3;    // D's ClientKey public key (C15); set with host_client_id
}
message DelegationRow {
  // 1-11 as today. A forwarding Delegation's row: tag_atoms empty, not_after 0, max_admits 0, admissions 0,
  // and reader_xwing_public_key (10) empty, its digest in 16
  bytes  forward_sidecar_id = 12;
  bytes  host_client_id = 13;
  bytes  host_client_public_key = 14;
  uint64 superseded_at = 15;           // the position of S's newer forwarding Delegation; 0 none
  bytes  reader_key_sha256 = 16;       // SHA-256(the Delegation's reader_xwing_public_key)
}

// sidecar/protocol/bridge/bridge.proto
message BridgeIdentity {
  // 1-5 as today
  bytes forward_delegation_id = 6;     // the subject's forwarding Delegation live at the state, 32 B; empty none
  bytes forward_public_key = 7;        // its Ed25519 key, 32 B
}
message Pending {
  // 1-4 as today
  bytes forward_delegation_id = 5;     // the forwarding Delegation this component's keys are named in
}
message ForwardingKeys {               // VPN component -> sidecar role: public halves only
  bytes key_set_id = 1;                // 16 random bytes naming this set of keys
  bytes forward_public_key = 2;        // Ed25519, 32 B
  bytes reader_xwing_public_key = 3;   // 1,216 B
  bytes client_public_key = 4;         // F's ClientKey public key
  bytes host_client_id = 5;            // D, where this network is D's
  bytes host_client_public_key = 6;
}
message ForwardingHandOff {            // sidecar role -> VPN component; never logged (I-7)
  Pending pending = 1;
  bytes  key_set_id = 2;
  bytes  forward_client_id = 3;        // F
  string forward_client_jwt = 4;
  int64  strict_exp_ms = 5;
  bytes  config_repo_id = 6;
  bytes  config_group_id = 7;
  bytes  signed_delegation = 8;        // the Signed Delegation as filed
  AuthPin delegation_at = 9;           // the log position that carried it
}
```

**The reader key leaves rows.** A forwarding Delegation's statement keeps its `reader_xwing_public_key` (the log entry is 1.4 KB once), its row carries the key's SHA-256, and the key itself is an object at gkm, `gkm/dkey/<delegation_id hex>`, 1,216 B, created If-None-Match by the Delegation's signer through `PUT /gkm/delegation-keys/<delegation_id>` and read by any config reader through `GET`. gkm requires the body's SHA-256 to equal the row's digest; a rotator takes the key from the statement where it holds the entry and else from the object, checks the digest, and seals the DelegationWrap, whose `recipient_key_sha256` is the same digest. With it 5,000 devices' rows are 2,181,164 B and the cap sits near 9,600 devices (4.4). An auth key's Delegation keeps its key in its row: a network has a handful. (Question details-4-forwarding-reader-key-in-rows.)

**A window delegation's signer** is read from `signer_id`'s length, never by trying keys (QD-093): 16 B is a `sidecar_id` and the identity key; 32 B is a `delegation_id`, `key_id` the SHA-256 of the forwarding public key, and the delegation verifies only under `BridgeIdentity.forward_public_key` of the subject it names, whose `forward_delegation_id` equals `signer_id`.

**The component's store**, per network, in the VPN component's own container (never an app group):

```text
key store (SidecarForwardKeyStore, the platform stores §5.9 names); net8 = the network id's first 8 B, hex
  fwd.<net8>.<slot>.sign     the forwarding key's Ed25519 seed, 32 B          slot = current | next
  fwd.<net8>.<slot>.reader   the X-Wing seed, 32 B
  fwd.<net8>.<slot>.client   F's ClientKey seed, 32 B
  fwd.<net8>.<slot>.id       key_set_id, 16 B, and once handed off the delegation_id, 32 B
  fwd.<net8>.root            the forwarding root key, 32 B random, which seals the files below
  fwd.<net8>.token           F's jwt, replaced at each refresh
  fwd.<net8>.floor           u64be(n) || A_n, 40 B: the highest pin this component committed
files, each sealed (below), under fwd/<network_id hex>/
  posture/<name>             device.PostureStore's records: manifest, base entry, rows, entries, state
  log/<n, 20 digits>         the entries from the newest base's retention point up to that base, which the judge
                             re-applies by the base's tail_verdicts; dropped when a newer base's point passes them
  head/<config_head_sha256>  a verified config head's files, the newest two kept
  gen/<g, 20 digits>         RK_g with its Signed GenRotate, every generation opened
  setup                      the ForwardingHandOff without its token
sealed record  "UFS1" || file id (16 random B) || chunks of 64 KiB plaintext, each AES-256-GCM under
               HKDF-SHA256(root key, salt file id, info "urnetwork-sidecar-v1/forward-store" || name),
               nonce u32be(0) || u64be(chunk index), AAD name || file id || u64be(index) || u8(final)
```

AES-GCM because `sidecar/device` may import only std, connect and `protocol/bridge`; a per-file key makes the counter nonce safe; the final-chunk byte detects truncation; the name in the key and AAD stops a record being moved. Rows stream through it in 64 KiB chunks, never held whole.

**Settings.** `ForwarderSettings` (root; `DefaultForwarderSettings(hostClass)` fills them): `CompileDelay` 2 s, `CompileMinInterval` 10 s, `CompileRetryInterval` 30 s doubling to 10 min, `CompileMemoryMaxByteCount` (Apple extensions 10 MiB, Android 16 MiB, desktop services 64 MiB), `CompileHeapCeilingByteCount` (Apple extensions 30 MiB, else 0 for none), `FollowInterval` 1 h, `FollowPageMaxCount` 64, `KeyWaitAlarmInterval` 10 min, `HeadCacheCount` 2, `FreeMemoryAfterCompile` (mobile classes). `PostureSettings` gains `NarrowingOverdueTimeout` 10 min: how long a narrowing entry the posture cannot check waits before `bridge_alarm` is raised for it, and the period at which the alarm is raised again while it waits (4.2.5).

#### 4.2.3 The binary split

```text
links in the leg      sidecar/device and sidecar/protocol/bridge, as today
                      the root, built with ios_extension, only the files on the leg's list: the closure of
                        bridge_forward*.go (BRIDGE-M8-05) and the compiler, 269 of 428 root files today
                      sidecar/protocol, 15 of its 17 generated files (mail.pb.go and socket.pb.go leave)
                      sdk's device_sidecar*.go, which name the root only through the Forwarder
leaves, by tag        every other root file: all 32 mail_, 22 mls_, 16 host_ and 5 search_ files, 15 of 17
                        smtp_, 8 of 10 socket_, 28 of 82 evs_ (evs_index_, evs_export, evs_git_), and the
                        rest of the 159, each under //go:build !ios_extension
leaves, by module     mox, adns, go-smtp, go-message, go-imap, miekg/dns, acmez, pebble, the MCP sdk, brotli,
                        yaml.v3, golang.org/x/text/encoding, golang.org/x/net/html: none is imported by a
                        listed file, and make check refuses each in the leg's go list -deps
never linked          cli/, mcp/, every <svc>service, smtpproof, sidecarctl: other modules or packages
```

**Why a computed list.** The file closure was found by building the leg with every root and `protocol` file outside a growing set replaced by an empty one, adding the file that declares each undefined name until it compiles (ten rounds). It is 269 files because the root's files are not layered: 31 `record_`, 25 `rpc_`, 18 `identity_` and 11 `directory_` files are in it for a type or constant each. The linker then drops what nothing reaches, so the list's length does not set the size: of the 269, 118 hold any linked code. What the tags buy is the code and tables that a package-level variable or `init` roots, which no dead-code pass removes: `mox/publicsuffix` (335 KB), the `x/text` encodings (about 700 KB), `html`, `x/text/language`. Measured, the same entry points cost 2,004,152 B more unstripped without the tags, 1,885,888 B stripped. Cutting the list further (an `ios_extension` seam so the leg's files stop naming `record_` and `rpc_` types) is review-phase work the ratchet invites; it would shorten the list and barely move the size.

**The rules `make check` holds** (REPO-M4-01): the leg's root and `protocol` `GoFiles` are a subset of `check/testdata/ios_extension_leg.txt`, and a file outside it fails with the fix, which is the tag; the leg's closure holds none of the modules above and none of `net/rpc`, `text/template`, `html/template`; the list shrinks freely and grows only in a commit that edits it. sdk's `TestIosExtensionRegistersOnlyBridgeDescriptors` reads the same list.

**Protobuf.** The leg keeps `google.golang.org/protobuf` and the generated code: the runtime is in the extension already through connect (it adds 80 B), and `protocol`'s linked symbols are 338,076 B. A hand-written decoder for the leg would save under half a megabyte and fork every format the judge reads; the one streaming scan that exists, the posture's pass over rows, stays. `protoc-gen-go` emits no build constraint, so protocol/Makefile adds `//go:build !ios_extension` to `mail.pb.go` and `socket.pb.go` after generation.

**Crypto.** Everything the leg needs is in the Go standard library and already linked by connect: Ed25519 (`crypto/ed25519`) to verify statements and sign delegations and DPoP proofs; HPKE-XWing (`crypto/hpke`, KEM 0x647a, over `crypto/mlkem` and X25519) to open DelegationWraps, open only; AES-128-GCM inside HPKE and AES-256-GCM for the store; ChaCha20-Poly1305 (`x/crypto`, linked by connect) for sealed config bodies and evs; SHA-256 and HKDF. Measured, the leg adds 13,296 B of crypto symbols, all Argon2 and BLAKE2b reached through `keys_unlock.go`, which forwarding never calls and a later cut removes. No MLS: no `mls_` file is in the closure, since a forwarding Delegation reads by wraps and is never a leaf. No third-party post-quantum library.

**Sizes**, ios/arm64, a probe that keeps alive connect's whole exported surface (the baseline `make size` uses) plus what each row names:

```text
probe                                                        unstripped     stripped    added, stripped
baseline: connect and connect/protocol                       37,789,784   34,217,792
+ device and protocol/bridge (the leg today)                 39,017,184   35,301,048      1,083,256
+ the root with 18.10's kept list, no tags (od197 as written) 45,767,912   41,340,840      7,123,048
+ the forwarding entry points below, no tags                 45,543,272   41,143,928      6,926,136
+ the forwarding entry points below, the 269-file list       43,539,120   39,258,040      5,040,248
entry points: the rows-only ConfigLog, OpenConfigBody, NewConfigHead, NewAclState and ParseAclPolicy,
  ParseGkmDelivery, OpenGkmDelivery and OpenGkmLadder, GkmApi's Generations and Wraps, EvsRepo.ReadHead,
  SidecarApi's Refresh, ExchangeToken, AuthClient, GetIdentity, ReadConfigProjection and SyncPoll
of the last row's 5,217,578 B of added symbols: pclntab and runtime tables 1,887,560; type data and other
  963,408; the root 952,643; protocol 338,076; device 246,556; strings 175,640; protocol/bridge 97,576
segments, stripped: __TEXT +3,981,312; __DATA_CONST +950,272; __DATA +98,304
not yet built, so not in any row: bridge statements, the compiler, the Forwarder and its signer; estimate
  350,000 B stripped: about ten files at the config rule files' 8.9 KB of code each, times the leg's
  measured 3.1 B of stripped binary a byte of package code, rounded up
```

The budget this section proposes (question details-4-ios-forwarding-budget): the leg adds at most **6 MiB, 6,291,456 B, measured stripped** over the pre-sidecar extension, against 5,040,248 B measured and about 5.4 MB expected; the signed extension's ceiling rises from 50 MiB to 54 MiB as §18.10 proposes (47,738,704 B on 2026-11-02 plus 5.4 MB is 53.1 MB, 3.5 MB under 56,623,104 B). `make size` measures stripped because sdk/build/Makefile ships `-s -w` and `check_apple_size.sh`'s ceilings read that binary; this also closes sdk-m4-02-make-size-over, whose option 2 it is. The 4 MiB of §18.10 cannot be met by the shared judge. Of the root's 952,643 B of linked code, the config rule table and state are 276,864 B, the evs read path 243,936 B and the ACL state 162,416 B, each before its tables, and the same probe without evs head reads, gkm's client or the poll still adds 4,400,320 B stripped.

#### 4.2.4 The memory plan

The tunnel's limit is the binding constraint, not its executable. The plan has three parts.

**Nothing of the network stays decoded between compiles.** Steady, the component holds per network: the compiled `BridgeState` inside `device.Bridge` (the table, per-subject rows, identities at about 160 B with a forwarding key, names at about 80 B), the posture's in-memory part (the pin, has_document, the config writers' keys, the overlay), the pin table (1,024 slots on mobile) and the `Forwarder`'s timers. The rows, entries, heads and generation keys are files. For a personal network that is under 300 KB; for a 5,000-device team in which every device reaches this one, about 2 MB (estimate). The gate stays §18.10's 4 MiB steady, which SDK-M8-15's cell samples.

**A compile is admitted by an estimate and bounded by the process.** Measured with the landed loader (`configLoadRows` over a fixture of n devices in n/3 members, two devices in three with a forwarding row in 4.2.2's form, three repos a member, a 1,024-entry ring):

```text
devices    rows bytes    decoded and loaded    ratio     with the reader key in rows (today's row)
      6        11,435          144,104          12.6          15,895 ->    153,888
    100        55,638          361,472           6.5         130,343 ->    434,352
  1,000       461,206        2,331,144           5.1       1,204,911 ->  3,056,936
  5,000     2,181,164       10,528,336           4.8       5,898,574 -> 14,161,032   (rows over 4 MiB)
 20,000     8,644,252       40,961,848           4.7      (rows over 4 MiB either way)
estimate(compile) = 5 x rows_byte_count + 2 x head byte count + the newest base's tail bytes + 1 MiB
admit iff  estimate <= CompileMemoryMaxByteCount
      and  (CompileHeapCeilingByteCount = 0 or heap in use + estimate <= CompileHeapCeilingByteCount)
```

Section 5.4 estimated two to three times the bytes; the measurement is five, because a row decodes into a struct and a separate allocation for each id, key and hash it holds. In the Apple extensions the cap is 10 MiB and the ceiling 30 MiB, under the tunnel's 32 MiB soft limit: rows up to 1.8 MiB compile, about 4,300 devices at this fixture's mix, when the tunnel sits at its measured 19.6 MiB; under provider load (26.0 to 27.4 MiB) only 770 to 1,440 devices' rows fit at that moment and the compile is deferred. A compile that the cap refuses raises `bridge_alarm` (`compile_over_budget`) and never runs on that device; one the ceiling defers retries at `CompileRetryInterval` and raises `compile_deferred` after 10 min. Either way the last verified state stays in force and denials keep applying. A narrowing entry that waits meanwhile raises 4.2.5's alarm at 10 min and each 10 min after, and never forces pending (QD-621, which QD-620's answer now follows): a network refused for memory keeps forwarding by its last compiled state. A network already over the cap when a device first sets it up has no compiled state to keep: it is pending there with `compile_over_budget`, as every network is before its first compile, and works on Android, Windows and Linux. (Question details-4-ios-compile-memory, option 1; QD-620.)

**Past the cap: a storage-backed compile, in the review phase** (QD-641). The owner's direction of 2026-11-10 is that the SDK, the apps and their VPN components keep bulk state on storage, of which a phone has far more than RAM, and treat RAM as a working set; the 10 MiB cap is a bound on RAM, not a reason to hold a network's rows in it. So the path for networks past about 4,300 devices in the Apple extensions is not the compact per-host state in the shared verifier that question details-4-ios-compile-memory named as its option 4. It is the same compile reading its rows from the sealed store:

```text
rows      stay in the store as the posture streamed them there, sealed in 64 KiB chunks; beside them an index the
          follow writes as they stream: for each row kind, id -> chunk and offset, sorted, itself a file
judge     RestoreConfigLogRowsOnly takes a row source in place of decoded rows: an entry is judged against the
          rows it names (its signer, its target, the proposal or Delegation it cites), each read through the
          index and decoded alone, with a bounded cache of chunks and of decoded rows
tail      the rows the tail's entries change are kept as an overlay over the row source, in RAM: at most 4,096
          entries' worth, since a base leaves no more unfolded (section 5)
compile   CompileBridgeState and NewAclState stream the rows once, in order, each row decoded, tested for whether
          it reaches or is hosted by S, used and dropped; what is kept is the compiled state, which is
          proportional to what reaches this device
RAM       the index's top level, the caches, one row, the tail's overlay and the compiled state: a working set
          the admission rule estimates from the caches' bounds and the last compiled state's size, under the
          same 10 MiB cap and 30 MiB ceiling, whatever the network's size up to §8.8's 4 MiB of rows
```

No format changes: `ProjectionRows` is read as it is written, and the index and the caches are local. It is a change to how `ConfigState` reads rows, in landed core-lane code, so it is review-phase work with that lane, measured on the ios32 surrogate by SDK-M8-15's cell. Until it lands the cap stands as above, and §22.9's cell stays "a 3,000-device team compiles within the cap and a 5,000-device one is refused with the alarm"; when it lands the cell becomes "a 5,000-device team compiles within the cap", and the estimate's `5 x rows` term goes. The steady state already follows the direction: between compiles nothing of the network is in memory but the compiled tables.

**A compile gives its memory back.** It holds no reference past its hand-off, and on mobile classes calls `debug.FreeOSMemory`, which on darwin returns pages by `MADV_FREE_REUSABLE`, the form `phys_footprint` accounts. The static cost of the larger binary is bounded above by the growth of the segments the loader may dirty, 1,048,576 B (`__DATA_CONST` and `__DATA` above), and its start heap is measured by a native darwin/arm64 probe after a collection at `main`: 912,656 B at the baseline, 1,007,296 B with the device role, 1,537,952 B with the leg, so 625,296 B for the added descriptors and rule tables.

Links are unchanged: a window client carries a full client graph, and the iOS tunnel runs none until §22.9 measures one (owner decision 100; `LinkCountMax` 0).

#### 4.2.5 Verification

**What tier 1 checks, and what it does with each entry.** The posture verifies, as landed: the chain from its pin; a base's Signed header under a config writer named in the rows it holds (the previous base's, or for its first base the base's own, as a cold gate starts); `rows_sha256` over the rows as they stream to the store; and each statement's signature under its signer's identity key in those rows. A base's `tail_verdicts` it stores and does not read: verdicts reach it only as a compiled state. Then, by SignedType:

```text
applied as a denial, at once   SidecarRevoke, MemberRevoke, Suspend, GrantRevoke, BridgeWithdraw (as landed)
(overlay; never an opening)    DelegationRevoke: denies the forwarding key of the delegation_id it names
                               Delegation whose field 7 names its own signer: denies that sidecar's
                                 forwarding key under any other delegation_id (supersession)
                               a covered SidecarRevoke, MemberRevoke or Suspend counts on its identity
                                 signature alone; the judge checks the countersignature (decisions 185, 187)
narrowing, not applied         any of the above that the posture cannot check: its signer is not in the stored
(joins Waiting, starts the       rows, its signature does not verify under the key those rows hold, its signer's
alarm clock; never pending)      class is short, or (a DelegationRevoke) it names no forwarding Delegation in the
                                 state; and every AuthorityProposal, AuthorityCosign, RecoveryRebind, AdminSet,
                                 BridgeEgress and TICK, and every BASE whose config_head_sha256 differs from
                                 the stored base's
opening or neutral             everything else, Unsuspend included: wants a compile, starts no clock
wrong network, broken chain    not an entry of this log: head_alarm (fork), nothing applied, pin unmoved
```

The posture lifts nothing: an Unsuspend is an opening and waits for the compile, where the landed code lifts an overlay Suspend on its own class check. `Waiting` records each narrowing entry's position and the time it was first seen, in the manifest, so a restart does not reset the clock.

A waiting entry never changes what the component enforces (question details-4-compile-deadline, option 2; QD-621). The posture is never pending because of one: the last compiled state stays in force, with every denial the posture could check applied on top, and the next compile judges every waiting entry. When one has waited `NarrowingOverdueTimeout` (10 min) the decision reports `Overdue`, the position and age of the oldest waiting entry, and the posture raises `PostureAlarmCompileOverdue`, which reaches the owner as `bridge_alarm` with reason `narrowing_overdue`, the entry's position and its age. It is raised again each `NarrowingOverdueTimeout` for as long as an entry waits past its own, and stops at the state that judged them. `device.Bridge` shows `Overdue` in its status and enforces nothing by it. The Forwarder's timer wakes at the next alarm time and reads the sink's `Decision()`, where the posture raises it; `PostureSettings.Now` is read for nothing else.

The cost is the owner's to accept, and is accepted: a revocation the posture cannot check does not apply on a device that cannot compile, for as long as it cannot. Three kinds of device are in that state for longer than a compile's delay: one whose network is over the memory cap (4.2.4), one under sustained provider load, and one that cannot reach gkm or evs for a generation or a head. Each raises its own alarm as well. What a compile's absence never does is open anything, and it never holds back a revocation the posture can check, which is every one signed by a device in the rows it holds.

**A state.** `Posture.SetState(state, log)` accepts a state only when: its pin is on the posture's chain and at or above the state in force (a lower one is dropped, not an error); the log run verifies from the state's newest base through its pin; `has_document` equals the verified rows'; and a move from doc to nodoc rests on a verified base above `document_seen_at`. On acceptance the overlay and `Waiting` keep exactly the entries above the state's pin, since the state embodies every verdict at or below it, and the posture's pin becomes the larger of the two. Then it commits and raises the floor.

**The Forwarder**, one per network, in root files on the leg's list:

```text
ReceiveHint(position) | timer(FollowInterval) | start | Witness(pin, fork):
  Follow:
    loop  page := api.ReadConfigProjection(after = the newest stored entry)   -- F's token (forward_only)
          store.AppendEntries(page.Entries); store.PutRows(page.Rows)  -- sealed; rows stream
          if the posture is enforcing: sink.ApplyDeltas(PostureLog{page.Entries, OpenRows})
                                                                       -- tier 1: chain, base, denials
          until not page.More or FollowPageMaxCount pages
    if any entry this follow was not applied as a denial, or the posture is pending with an anchor,
       or Waiting is not empty:  schedule Compile after CompileDelay (single-flight; at most one each
       CompileMinInterval; a hint during a compile schedules exactly one more)
  Witness: Follow up to pin; pin not on my chain -> head_alarm(fork) with both pins;
           fork = true -> sink.SetFork(true): the posture enforces pending, and no compile runs, until a
           later Witness with fork = false

Compile:                                                 -- captures cPin := the newest stored entry
  0 admission (4.2.4); refused or deferred -> alarm, keep the state, return
  1 judge    log := RestoreConfigLogRowsOnly(settings, retained{genesis, the newest base, its tail from log/},
                      rowsSource = the store, floor)     -- section 5: StartAtBase at the base by its bits
             log.ApplyRun(the entries (base, cPin], 256 at a time)   -- Judge each at id level
             any error or fork -> alarm state_unverified, keep the state, return
  2 keys     for each generation g a sealed body or the head names and gen/<g> does not hold:
               GkmApi.Generations(since) -> ParseGenRotate; GkmApi.Wraps(g, recipient = my delegation_id)
               -> ParseGkmDelivery(SIGNED_DELEGATION_WRAP) -> OpenGkmDelivery(reader key) -> RK_g;
               OpenGkmLadder downward; store gen/<g>
             no wrap yet -> ask late once a LateAskInterval; bodies of that generation stay pending
               (BRIDGE-M2-01's id-level effect); alarm config_key_waiting after KeyWaitAlarmInterval
  3 head     if head/<base.config_head_sha256> is not stored: EvsRepo.ReadHead of the config repo at
               base.config_version with the exchange's repo:<config_repo_id>:r token; require its chain value
               to equal config_head_sha256; NewConfigHead(files); require rows.settings to equal the head's
               ServiceSettings and rows' has_document to equal whether it holds a policy; store it
             unreadable now -> keep the state, retry; another head than the one named -> head_alarm
  4 compile  acl := NewAclState(rows.acl, log.State()); state := CompileBridgeState(view{log.State(), head,
               acl, OpenConfigBody over gen/}, S)                       -- BRIDGE-M4-16
  5 hand     sink.SetState(state, PostureLog{entries from the base through cPin, OpenRows})
  6 release  the posture committed the state and raised the floor in step 5; drop log, head, acl and
             state; FreeOSMemory on mobile classes
```

The judge is the rows-only `ConfigLog` and no other: the code path api and the gates take, with section 5's rules unchanged. The Forwarder adds what a gate lacks, the reader key, and uses it only in steps 2 to 4. It checks the head against the base (step 3's three equalities) but does not re-compile rows from it: that is a full reader's check, and the app's sidecar role makes it. A compile that fails at any step changes nothing.

**What a host does with a forwarding-key principal.** `VerifyPrincipal` admits a 32-byte-signer delegation as 4.2.2 says, from the compiled state. `ResolveEgress`'s per-flow recheck then denies it while the overlay holds a `DelegationRevoke` of its id, a supersession of its sidecar, or any denial of the subject, and `Bridge.Revoke` closes its flows after the policy swap (D-BRIDGE-21's order). So a revoked or replaced forwarding key stops at the host as fast as the entry arrives, compile or no compile, and the replacement key is admitted only after the compile that judged its Delegation.

**Restart.** The posture restores from the sealed store before the first packet, as landed, and then checks the floor: a manifest pin below `fwd.<net8>.floor`, or equal on another chain, is a rolled-back store, which is pending with `store_rolled_back` until a follow brings the pin back to the floor on the floor's chain. The floor is as strong as the platform's key store: on Apple a keychain item outside the container; on Android, Windows and Linux a sealed file beside the seeds, which stops a restored copy of the state files but not a process that already holds the seeds.

#### 4.2.6 The forwarding key's lifecycle

```text
states, per network, in the VPN component (C) and the sidecar role (S)
  none        no key set: legacy
  generated   C made a key set in slot next and gave S its public halves (ForwardingKeys)
  delegated   S's forwarding Delegation naming them is in the log at n; F minted; hand-off delivered
  active      C's own posture holds a state at or past n that shows that Delegation live: slot next
              becomes current, the signer signs with it, the old set is deleted
  superseded  a newer Delegation of S is in the log: hosts deny this key from that entry (4.2.5)
  revoked     its DelegationRevoke, or S's revocation or void: denied at every host from that entry
  lapsed      F unrefreshed past its strict_exp (the component off 7 days): pending until a new hand-off
  wiped       S's own sign-out (its SidecarRevoke, verified as plan-SDK-pending-sidecar-id says): keys,
              store and floor erased; legacy

setup (BRIDGE-M8-06 in S, SDK-M8-16 in C, SDK-M8-07 between them), each step idempotent
  C0  keys := generate(Ed25519 seed, X-Wing seed, ClientKey seed) into slot next under a fresh key_set_id;
      reply ForwardingKeys (a repeat while next is unpromoted returns the same set)
  S1  write record forward/<network>/setup {key_set_id, public halves, step}; sign Delegation{pubkey,
      reader_xwing_public_key, forward{S, D and D's key in D's network}}; delegation_id = SHA-256(Signed);
      record the Signed bytes
  S2  POST /network/config/delta; WaitFor its position n            (409 at the tip: re-sign at the new pin
                                                                     and record again)
  S3  PUT /gkm/delegation-keys/<delegation_id>                      (409 until gkm's state holds the row)
  S4  write the late DelegationWrap of the config's current generation to that key (10.5's dwraps)
  S5  POST /network/auth-client {source S's client, admin_refused, strict_exp, forward_only,
      client_public_key} with S's DPoP proof -> F                   (a repeat for the same key reuses F)
  S6  return ForwardingHandOff
  C7  check signed_delegation: its pubkey, reader key and, where set, host client equal slot next's and
      this device's, forward names pending.sidecar_id, and it verifies under pending.identity_public_key;
      else refuse and keep current. Store the token and setup; SetPending if legacy; Follow
  C8  when a state at or past delegation_at shows forward_delegation_id live for S: promote next to current,
      re-sign every live window client, delete the old set
when  S runs it at each new client generation of S (enrollment, re-enrollment, pairing), at any run of the
      app 90 days or more after the last, and when no forwarding Delegation of S is live; after a
      DelegationRevoke by a signer other than S, only once the person confirms in the app (never MCP)
kill  around S2: a repeat posts the recorded bytes again, and a copy already in the log is found there by
      its id, since the replay row refuses the second, so one Delegation is filed. After S2: the record's
      step resumes. Between C7 and C8: C keeps signing with
      current, which hosts admit until they apply the newer Delegation's entry, then with next after C8;
      the gap is at most one compile at each host, and links fail closed across it and rebuild
```

What each key may do, and where that is enforced: the forwarding key signs only `WindowDelegation`s naming S (hosts check the subject against the identity it is listed under; api and readers refuse a `SidecarAdmit` or `AdmissionConfirm` it signs); the reader key opens only the config's generations (its holder identity reaches the config alone, §10.5); F's token passes only TEAM-M8-02's allowlist and exchanges only for `repo:<config_repo_id>:r`. The component holds no key of S, and S holds none of the component's.

The key fits section 5 unchanged: a forwarding Delegation and its revocation are ordinary statements, judged once by the rule table at their positions, carried in `tail_verdicts`, folded into a `DelegationRow` with signer, position, `superseded_at` and `ended_at`. Section 5.2.3's guess of a `KeyRegister` purpose is not taken; its alternative, "`DelegationRow` already carries what this section needs", holds with fields 12 to 16.

### 4.3 Invariants and why they hold

```text
OnlyJudgedOpens      every reach the component enforces is in a state the rows-only judge compiled, at a pin
                     on the anchored chain
                     why: SetState is the only source of rules and identities; the overlay holds denial kinds
                     alone and the posture lifts nothing (4.2.5)
OnlyLiveKeysAdmitted a host admits a delegation under forwarding key k only while k is S's live forwarding
                     key at the highest position the host ever applied, or while a revocation of k that the
                     posture could not check waits for a compile
                     why: the state gives the key live at its pin; every entry that ends it (revocation,
                     supersession, suspension, S's revocation) is a denial kind applied on its signature; the
                     one exception is a revocation the posture cannot check, which waits for the next
                     compile; a state keeps the overlay above its pin and never replaces a higher state; a
                     store below the floor is pending
RevocationsLand      (liveness) where fetches go on and compiles start and finish, in the end every key the
                     host admits is S's live key at the newest entry: a revocation the posture cannot check is
                     refused by the first compile that captured a pin at or past it
                     why: that compile's judge applies the entry by the rule table, and its state replaces
                     the one in force. Where no compile finishes this does not hold: the key stays admitted,
                     and bridge_alarm says so from 10 min on. That case is accepted (QD-621)
DP1                  after a device's first verified state, no restart, delay, unsigned input, lower state or
                     rolled-back store lowers enforcement
                     why: as SDK-M4-01 built it, plus the floor and the lower-state rule
StalenessBound       the enforced reach is the reach judged at the state's pin, minus the applied denials
                     after it; a narrowing entry the component has fetched and no compile has judged is
                     older than 10 min only with bridge_alarm raised for it, and raised again each 10 min
KeysStayPut          no private key of the component crosses the device RPC or a function boundary to the
                     sidecar role, and none of S's enters the component
                     why: ForwardingKeys holds public halves and the hand-off holds a token and public data
OneJudge             the component accepts no verdict but the rule table's: the posture's checks decide only
                     denials, and a compile failure changes nothing
```

**The model.** `Fwd.tla` keeps the log of one sidecar S (forwarding Delegations, their revocations, S's suspension, unsuspension and revocation) and one host's forwarding role: the posture's pin, the compiled state's pin and key, the overlay, compiles in flight that finish in any order, a key-store floor, and a copy of the store that an attacker puts back. Each entry carries `ok`, whether the rule table accepts it (a refused entry is one api sequenced that verifies under its signer's key), and a revocation carries `seen`, whether the posture holds its signer's row. The judge is section 5's S(n) reduced to S's forwarding row. `Tick` marks the entries then waiting as past their deadline, which raises the alarm for them and changes nothing the host admits. It leaves out the delegation's other fields, share signers, `strict_exp` and every other subject. `Twin` breaks one rule; `run-fwd.sh <track>` runs every configuration through `.stack/tools/tlc` and prints a verdict line per run.

The model as amended for QD-621. `Admits` no longer asks that no waiting entry be past its deadline, which was the design and is the rule the owner declined; the twin `NoOverdue`, which removed that rule, is gone, being the design now. The safety invariant `OnlyLiveKeysAdmitted` is restated: a key the host admits is S's live key at the highest position applied, or a revocation of that very key which the posture could not check is waiting for a compile, with no limit on how long. Eventual refusal is a temporal property, `EventuallyRefused` (in the end every admitted key is S's live key at the newest entry), checked under `LiveSpec`, whose fairness is exactly "a compile eventually runs": fetches go on, a compile starts whenever a slot is free, and a compile that keeps being started is in the end let finish. Two reach configurations record the case the owner accepted. `FwdReach-NoCompile` denies the declined rule as an invariant, `RefusedByDeadline`, and TLC answers with the trace: S's forwarding Delegation and then its revocation, which the posture cannot check, are sequenced; the host fetches both; a compile that captured its pin before the revocation finishes and admits the key; the revocation waits; its deadline passes and the alarm is raised; the key is still admitted. `FwdReach-NoCompileLive` checks `EventuallyRefused` under `FetchSpec`, fairness of fetches alone, and TLC answers with a loop in which a compile is started and restarted and never finishes. `StaleIsAlarmed` holds that whenever a key that is not live is admitted and every waiting entry is past its deadline, the alarm stands.

Runs, TLC at the owner's jar (master d8fb231), breadth-first over every reachable state at the bounds, 14 workers, all made again on 2026-11-10 on the amended model, on a machine carrying four build lanes:

```text
configuration                Twin                  bounds                                 result
                                                                              distinct states  depth  time
Fwd                          none                  4 entries, 2 keys, 2 compiles in flight
                             pass: OnlyLiveKeysAdmitted, OverlayAfterState,
                             StaleIsAlarmed                                        35,190,248    19   12 min 15 s
Fwd-Rollback                 none                  4 entries, 2 keys, 1 compile, the store copied and put back
                             pass: the three                                       49,904,532    22   7 min 2 s
Fwd-Live                     none                  3 entries, 2 keys, 1 compile, under LiveSpec's fairness
                             pass: the three, and the property EventuallyRefused      189,942    14   12 s
FwdTwin-NoDelegationOverlay  NoDelegationOverlay   3 entries   OnlyLiveKeysAdmitted violated, 7-state trace
FwdTwin-OverlayLifts         OverlayLifts          4 entries   OnlyLiveKeysAdmitted violated, 9-state trace
FwdTwin-OverlayOpens         OverlayOpens          3 entries   OnlyLiveKeysAdmitted violated, 3-state trace
FwdTwin-StateDropsOverlay    StateDropsOverlay     3 entries   OnlyLiveKeysAdmitted violated, 7-state trace
FwdTwin-LowerStateAccepted   LowerStateAccepted    3 entries, 2 compiles   OnlyLiveKeysAdmitted violated, 9 states
FwdTwin-NoFloor              NoFloor               3 entries, rollback     OnlyLiveKeysAdmitted violated, 9 states
Fwd.tla, the design, with a rule it does not hold denied: the accepted case (QD-621)
FwdReach-NoCompile           none                  3 entries, 2 keys, 1 compile; the declined rule as an invariant
                             RefusedByDeadline violated, an 8-state trace
FwdReach-NoCompileLive       none                  the same bounds under FetchSpec, fairness of fetches alone
                             EventuallyRefused violated, a 10-state trace that ends in a loop
```

The two large graphs are the graphs first recorded, state for state: the deadline never changed what the host does, only what it admits, which the invariants read. Each twin run took under 5 s and stopped within 750,000 states. Two of the twins are the text and code as they stood: `NoDelegationOverlay` is §17.8's overlay list on 2026-11-09 (a revoked forwarding key admitted after its revocation's entry was applied), and `OverlayLifts` is the landed posture (an Unsuspend the rule table refused reopens a suspended sidecar's key). `StateDropsOverlay` and `LowerStateAccepted` are the two ways a compile racing later entries can lose a revocation; `OverlayOpens` is the shortcut of taking a newer Delegation's key without a compile; `NoFloor` removes the bound this section adds. `NoOverdue`, which removed the other, is no twin any more: the deadline it removed is not in the design, and what it showed is `FwdReach-NoCompile`'s trace, recorded as accepted. A fold needs no case of its own in the model: the posture reads no verdict from a base, and the judge restores from the newest base at each compile, which is section 5's `StartAtBase`, checked there.

### 4.4 Cost

```text
executable, stripped, the leg over the pre-sidecar probe; cgo off but for ios
  ios/arm64       34,217,792 -> 39,258,040   +5,040,248    budget 6,291,456; the device role alone +1,083,256
  darwin/arm64    35,387,122 -> 40,613,954   +5,226,832    the macOS extension's leg; +1,126,128
  linux/amd64     36,434,080 -> 41,779,360   +5,345,280    the Linux app service; +1,163,264
  windows/amd64   37,127,680 -> 42,607,616   +5,479,936    the Windows app service; +1,189,888
  android         not measured: the VPN service links the app's whole binding, sidecar role included, so
                  forwarding adds no leg there; the probe needs the binding's -checklinkname=0
  expected at M8  the measured rows plus about 350,000 B for the bridge files not yet built (estimate)
memory, the Apple extensions (4.2.4)
  static          at most 1,048,576 B of segments the loader may dirty; 625,296 B of start heap (native probe)
  steady          the compiled state and tables: under 300 KB for a personal network, about 2 MB at 5,000
                  identities (estimate); gate 4 MiB
  compile         4.2.4's estimate, transient: 1.1 MiB for a personal network, 3.2 MiB at 1,000
                  devices, 11.4 MiB at 5,000 (refused at the 10 MiB cap, until the review phase's
                  storage-backed compile reads the rows from the store: 4.2.4, QD-641)
  other hosts     Android 16 MiB cap, desktop services 64 MiB, no ceiling: the 4 MiB rows cap compiles in 21 MiB
wire
  setup           the Delegation's entry about 1.4 KB; the gkm key object 1,216 B; one DelegationWrap 1,168 B
                  plus its Signed envelope; one auth-client call; the hand-off about 2.5 KB in process or RPC
  each rotation   one DelegationWrap of about 1.2 KB a live forwarding Delegation: 6 MB at 5,000 app devices,
                  staged in 10.5's batches (§10.15's row stands)
  following       a hint, then one projection read: about 600 B an entry; at a base whose rows changed, the
                  rows: under 12 KB for a personal network, 2.2 MB at 5,000 devices, about once a fold
  compile         a head it has not cached; the GenRotates and one wrap of each new generation
  a contract      a WindowDelegation of about 200 B, 350 B with a ShareCert, and one Ed25519 verification
rows              a forwarding Delegation's row about 200 B, where the key in the row made it 1,300 B: the
                  4 MiB cap near 9,600 devices at the fixture's mix, against about 3,500 (2,600 if every
                  device is an app)
time              a compile at 5,000 devices: one 2.2 MB parse, one load and one pass, under 200 ms on a 2020
                  phone core (estimate, from 5.4's per-entry costs); a pure revocation needs none
```

### 4.5 Failure modes and recovery

```text
the app never runs again        forwarding goes on: F refreshes itself, follows and compiles; only setup
                                (a new client generation, a foreign revocation's confirmation) needs the app
the VPN component off 7 days    F lapses with no grace; at start the posture is pending (forward_client_lapsed)
                                and the app's next run mints another F for the same key set (S5 alone)
api or gkm unreachable          follows and compiles retry; the state stands; no clock runs for entries it
                                has not fetched (a host that hears nothing cannot be told to narrow)
a compile cannot run            over the cap: compile_over_budget, and the network never compiles on this device
                                until the review phase's storage-backed compile (4.2.4); over the ceiling:
                                compile_deferred, retried. Either way the state stands, denials apply and
                                nothing goes pending (QD-621)
a narrowing entry the posture   the state stands and forwarding goes on; bridge_alarm narrowing_overdue at 10 min
cannot check waits past 10 min  with its position and age, again each 10 min; the first compile that runs
                                judges it. Until one does, a revocation it carries does not apply on this
                                device: accepted (QD-621). An admin who needs it applied there sooner revokes
                                by a statement the posture can check, one signed by a device in the rows it
                                holds; a revoked sidecar is in any case refused its next forwarding client
                                by F's exchange (the row below)
a DelegationWrap is missing     the generation's bodies stay pending at id level, older ones compile, a late
                                ask goes out each LateAskInterval, config_key_waiting after 10 min; any
                                holder that is not read_only delivers (KF2's wrapped row)
the head cannot be read         the state stands and the compile retries; the base's id-level rows still feed
                                tier 1's denials
a lying config writer           a base whose rows do not compile from its head is not caught here (a rows-only
                                verifier); the app's sidecar role forks on it and sends Witness(fork), which
                                forces pending; between the app's runs the view is unwitnessed (§17.17's row)
a malicious api                 a refused statement it sequences can deny (availability, as withholding can)
                                until the next compile, never open; a forged entry breaks the chain or a
                                signature and is a fork alarm
the store is corrupt            pending, never legacy; a new follow from the anchor rebuilds it
the store is rolled back        pending with store_rolled_back until the pin is back at the floor
the key store is not Present    forwarding pending, never reset (§5.9); keys are made only at a setup
a kill during setup             4.2.6's kill row: one Delegation, one F, no key lost
a revoked sidecar's component   its own SidecarRevoke wipes it; an admin's revocation of S ends its Delegation
                                at every host, F's exchange refuses it, and its posture, applying the entry,
                                denies everything S hosted
the device is restored to       ThisDeviceOnly key items do not move, so the store state is not Present:
new hardware                    pending until the app enrolls and sets up again
```

### 4.6 The test plan

Unit tests, each a top-level `func TestXxx`, fake clocks and barriers only:

```text
device/   TestADelegationRevokeDeniesItsKeyAtOnce, TestANewerDelegationDeniesTheOlderKey,
          TestAnUnsuspendLiftsNothingUntilAState, TestAnUncheckableRevocationAlarmsAndKeepsTheState (the
          decision never pending, the alarm at 10 min and again at 20, across a restart, cleared at a state),
          TestAStateKeepsTheOverlayAboveItsPin, TestALowerStateIsDropped, TestARolledBackStoreIsPending,
          TestSealedRecordsRefuseEveryTamper, FuzzPostureNeverOpens                          (SDK-M8-17)
          the forwarding path's delegation vectors and each mismatch with its twin; an overlay revocation
          closing exactly its key's flows                                                    (BRIDGE-M8-04)
root      TestForwarderAppliesARevocationWithNoCompile, TestForwarderCompilesAfterAnOpening,
          TestForwarderJudgesAsARowsOnlyGate (its ConfigLog equals a gate's over generated logs with bases),
          TestForwarderAdmissionRefusesAndDefers, TestForwarderKillAtEachStepChangesNothing,
          TestForwarderOpensANewGenerationByItsWrap, TestForwarderHeadMustBeTheBasesHead,
          TestForwardingSignerSignsOnlyItsSidecar                                            (BRIDGE-M8-05)
          TestSetupResumesAfterEachStep, TestForeignRevocationWaitsForConfirm                (BRIDGE-M8-06)
          the forwarding row's refusals and supersession; rows equal across a fold           (TEAM-M8-01)
          a delegation key object refused off its digest; a rotation skipping a missing one  (KEYS-M8-01)
sdk       keys never cross (a capture of every call); two networks at once; next promoted only at the live
          state; F's refresh and lapse; the three RPC methods on DeviceRemote and an older peer (SDK-M8-16, -07)
check/    the leg's list, its refused modules and its size row, each with a planted failure   (REPO-M4-01)
```

Schedule rows. FS-38 gains the forwarding-key delegation (admitted; forged, superseded and revoked ones opening zero upstream sockets). §22.5's §17 row gains, on T2 and T3 with the app's sidecar stopped: a grant and a revocation within §8.9's targets; a `DelegationRevoke` racing a compile; a supersession racing a contract; a compile finishing below a newer state; a refused Unsuspend; an uncheckable revocation with compiles blocked: the state in force and forwarding uninterrupted, `narrowing_overdue` at 10 min and again at 20, and the revocation applied by the first compile let run (QD-621); the same on a network over the memory cap, which never goes pending. FS-18 gains KEYS-M8-01's cases. FS-14 gains a forwarding row across a fold at a new device and a gate. Each twin of `Fwd.tla` is one of these schedules on real code, and so is its accepted trace, `FwdReach-NoCompile`, which the code must reach with the alarm raised (BRIDGE-M8-07).

Gates. `make size`'s `ios_extension` row at 6,291,456 B stripped from M4. On the ios32 surrogate (owner decision 100): the compile cell at 3,000 and 5,000 devices, the steady heap after `FreeOSMemory`, the start heap, and the link cell (SDK-M8-15, BRIDGE-M8-03). Nothing here was measured on a device, and no surrogate figure is evidence for one.

### 4.7 The final task list and implementation notes

Each entry is in the area plans' format with one line added, `Change:`, which says new, changed, unchanged or dropped against the plans as they stand on 2026-11-10 and against `od-197-forwarding.md`, which this list replaces. Paths start at ROOT. A changed entry gives the task's final lines; a line it does not give stays as the plan has it.

#### New tasks

##### TEAM-M2-20: The forwarding Delegation's fields and the forward_only column before M2's freeze
- Change: new (od-197-forwarding.md's, amended: `ForwardScope` lives in auth.proto, `DelegationRow` gains `reader_key_sha256`, `Pending` gains the delegation id, and bridge.proto gains the two setup messages)
- Milestone: M2
- Repos: sidecar, server
- Size: S
- Spec: D-TEAM-33, D-SDK-32, I-18, owner decision 197, DESIGN-DETAILS 4.2.2
- Needs: TEAM-M2-01: `Delegation`, `DelegationRow`; running protos-bridge; TEST-M1-01: the v9 metadata list
- Provides: `bridge.ForwardScope{forward_sidecar_id = 1, host_client_id = 2, host_client_public_key = 3}` in auth.proto and `Delegation.forward = 7` of that type in config.proto; `DelegationRow` fields `forward_sidecar_id = 12`, `host_client_id = 13`, `host_client_public_key = 14`, `superseded_at = 15`, `reader_key_sha256 = 16`; `BridgeIdentity` fields `forward_delegation_id = 6`, `forward_public_key = 7`; `Pending.forward_delegation_id = 5`; `bridge.ForwardingKeys` and `bridge.ForwardingHandOff`; the nullable `network_client_owner.forward_only` column in MG8 under `sidecar_pending`
- Files: sidecar/protocol/config.proto, sidecar/protocol/config.pb.go, sidecar/protocol/bridge/auth.proto, sidecar/protocol/bridge/auth.pb.go, sidecar/protocol/bridge/bridge.proto, sidecar/protocol/bridge/bridge.pb.go, sidecar/config_records.go, sidecar/config_records_test.go, server/db_migrations_sidecar_pending.go
- Build: Formats only, as DESIGN-DETAILS 4.2.2 writes them, so they freeze with M2's records. `ForwardScope` is declared in auth.proto, not config.proto, because `sidecar/device` parses a Delegation's field 7 by wire and may import only `protocol/bridge`. A forwarding Delegation's row leaves `reader_xwing_public_key` (10) empty and carries its SHA-256 in 16: 1,216 B a device in rows would pass §8.8's 4 MiB at about 2,600 app devices (4.1's measurement). `forward` set means a forwarding Delegation; an older reader, which skips the unknown field, refuses the statement for its missing `not_after`, the closed direction. `ForwardingKeys` and `ForwardingHandOff` cross only the device RPC or a function call, so they take no §2.8 row. The column follows §19.7's MG8 line, never MG0.
- Tests: round trips and the schema guard's map for each new field; `FuzzConfigStatementType` with a forwarding Delegation; the migration pending under `sidecar_pending` and applying cleanly on the test stack.

##### TEAM-M8-01: Forwarding Delegations in the verifier and at api
- Change: new (od-197-forwarding.md's, with the row's digest and supersession position)
- Milestone: M8
- Repos: sidecar, server
- Size: M
- Spec: D-TEAM-33, D-TEAM-26, D-TEAM-30, I-4, I-15, FI-3, owner decision 197, DESIGN-DETAILS 4.2.6
- Needs: TEAM-M2-20; TEAM-M2-03: scoped signers; TEAM-M2-04: `ConfigState.DelegationEnded`, `DelegationKeyDropped`, the cascade; TEAM-M2-16: api's admission and removal; TEAM-M2-17: shrink and causal identities
- Provides: §7.9's forwarding row as a `configStatementRule`: `ConfigState.ForwardingDelegation(sidecarId)` (the live one, or none), supersession at the newer one's position (`superseded_at`), its ends and key drops; the refusals; api's host-client check; `DelegationRow` filled for forwarding Delegations with `reader_key_sha256` and no reader key
- Files: sidecar/config_forwarding.go, sidecar/config_forwarding_test.go, sidecar/config_delegation.go, server/controller/config_delegation_check.go, server/controller/config_delegation_check_test.go
- Build: A forwarding Delegation is signed only by its `forward_sidecar_id`'s identity key, that sidecar admitted, not read_only, not parked and not revoked at S(n-1); `tag_ids` empty, `max_admits` 0, `not_after` 0, `reader_xwing_public_key` 1,216 B and `pubkey` 32 B, each refused otherwise. api accepts it only if `host_client_id`, where set, is the source client of S's current bound client (`network_client.source_client_id`) and `host_client_public_key` that client's registered key. It admits nothing: api and readers refuse a `SidecarAdmit` or `AdmissionConfirm` whose signer resolves to one. A `DelegationRevoke` of one carries `since_n` 0 only, from S, a device allowed to revoke S (§5.6) or an admin. Ends: its revocation, S's revocation for any reason, its void when S is in a cascade's P. A newer forwarding Delegation of S supersedes it at the newer one's position: `superseded_at` is set, it is no end for §10.5 (no shrink), and a `DelegationRevoke` naming a superseded one takes effect and changes nothing live. Its key drops while S is parked or suspended and returns with S. Every effect is computable at re-application from the body and the rebuilt rows (DESIGN-DETAILS 5.2.3). Trap: D-TEAM-30's agent rules (tags, `max_admits`, `not_after` ≤ 90 d, parking admitted sidecars) must not apply to it.
- Tests: T1 tables per rule, each refusal with its positive twin: signed by another sidecar, with tags, `max_admits` or a `not_after`, a short reader key, a host client that is not S's source client; a `SidecarAdmit` signed by its key; a `DelegationRevoke` with `since_n` > 0. Supersession keeps one live per S and sets `superseded_at`; S's sign-out, a lost revocation and a compromise revocation each end it; a Suspend drops its key until the Unsuspend. Rows equal across a fold at a new device and a rows-only gate (FS-14's shape), field 10 empty and 16 set.

##### TEAM-M8-02: The forward_only mark, its allowlist, its proof key and its exchange
- Change: new (od-197-forwarding.md's, unchanged but for the allowlist's two reads)
- Milestone: M8
- Repos: server, sdk
- Size: M
- Spec: R-TEAM-8, D-TEAM-8, D-TEAM-14, I-6, I-7, owner decision 197
- Needs: TEAM-M1-04: the marks on `POST /network/auth-client`; TEAM-M1-01: the `strict_exp` allowlist; TEAM-M1-02: the DPoP verifier; TEAM-M1-06: the exchange; TEAM-M2-15: scopes from the projection; TEAM-M8-01; TEAM-M2-20
- Provides: `forward_only` on `POST /network/auth-client`, inherited by children; its narrower allowlist; the DPoP key from the mint's `client_public_key` for a client with no binding; the exchange's forwarding rule; the auth-client route's doc in connect/api/bringyour.yml
- Files: server/api/handlers/network_client_handlers.go, server/model/network_client_owner_model.go, server/api/route_authz.go, server/api/route_authz_test.go, server/session/dpop.go, server/session/dpop_test.go, server/oauth/exchange_scopes.go, server/oauth/exchange_scopes_test.go, connect/api/bringyour.yml
- Build: §7.4's mark row: `forward_only` takes a source client that is a bound sidecar client and its DPoP proof, and sets `admin_refused` and `strict_exp` too. The allowlist for a `forward_only` bearer: `GET /auth/refresh`, `POST /network/auth-client` and `POST /network/remove-client` for its own children, `POST /oauth/token`'s exchange, `GET /network/config/projection`, `GET /sidecar/identity/<sidecar_id>` and its `?client_id=` form, `GET /sidecar/sync/poll` for `team` hints, `GET /key/<id>` and `POST /connect/control`; every other route answers 403 as the sidecar allowlist does. With no binding, the proof key is the `client_public_key` its mint named. §7.8's exchange: a `forward_only` client gets only `repo:<config_repo_id>:r` at evs and gkm, and only while its sidecar's forwarding Delegation is live (TEAM-M8-01), whatever its sidecar reads. Trap: F acts as S at every gate (D-ACL-3), so without this rule F's token would exchange for all of S's scopes.
- Tests: a forwarding client's mint, refresh and child mint and removal with their proofs; every other route refused for its bearer and its window clients; the exchange answering only the config's `r`, refused once the Delegation ends or is superseded by one naming other keys; an `admin_refused` child without the mark unchanged.

##### KEYS-M8-01: The forwarding key holder and its reader key at gkm
- Change: new (od-197-forwarding.md's, amended: the reader key is a gkm object the row's digest names)
- Milestone: M8
- Repos: sidecar
- Size: M
- Spec: D-KEYS-16, D-KEYS-24, I-1, I-15, I-18, FS-18, owner decision 197, DESIGN-DETAILS 4.2.2
- Needs: KEYS-M2-03: `KeyHolders`; KEYS-M2-15: wraps; KEYS-M2-20: Rotate's delivery set; KEYS-M2-21: committers and seats; TEAM-M8-01
- Provides: `KeyHolders`' forwarding term: identity kind 5 (`forward` || sidecar_id), reach the config alone, live while §7.9's row keeps it; `gkm/dkey/<delegation_id>` with `PUT` and `GET /gkm/delegation-keys/<delegation_id>` and `GkmApi.UploadDelegationKey`, `GkmApi.DelegationKey`; a rotator's lookup of a forwarding Delegation's reader key; supersession as a key replacement with a late DelegationWrap, no shrink; its end as a shrink
- Files: sidecar/gkm_holders.go, sidecar/gkm_holders_forward_test.go, sidecar/gkm_api.go, sidecar/gkm_paths.go, sidecar/gkmservice/delegation_keys.go, sidecar/gkmservice/delegation_keys_test.go, sidecar/gkmservice/wraps.go, sidecar/gkmservice/wraps_test.go, sidecar/gkmservice/reconciler.go, sidecar/sidecartest/fs_keys_delegation_test.go
- Build: §10.5's table rows. The object is the 1,216 B X-Wing public key, created If-None-Match by the Delegation's signer; gkm requires SHA-256(body) to equal the row's `reader_key_sha256` at its newest verified state, answers 409 until that state holds the row, and equal bytes resume. Any token that reads the config repo may GET it. A rotator takes a forwarding Delegation's key from the statement where it holds the entry, else from the object, and requires its SHA-256 to equal the row's digest before it seals to it; a wrap's `recipient_key_sha256` is that digest, which gkm's wrap check compares with the row. A rotation stages one DelegationWrap per live forwarding Delegation in the config group; one whose object is missing is skipped and counted, and delivered late once it exists. The sidecar that signs a forwarding Delegation uploads the object and then writes its late DelegationWrap at the config's current generation (§10.5's dwraps). A newer forwarding Delegation of the same sidecar keeps the holder identity, so `holders_sha256` is unchanged and the new key gets a late delivery; a `DelegationRevoke` of the live one, or its sidecar's revocation, is a shrink and the next generation is cause REMOVE. The reconciler deletes the object 24 h after its Delegation ended or was superseded. `metadata_list.yml` gains the object under gkm-1 through design-records first (I-18); the key is a value rows showed before this change.
- Tests: FS-18's forwarding cases: a rotation wraps to the live forwarding key and not to a superseded one; a supersession changes no `holders_sha256`; a `DelegationRevoke` makes the next generation REMOVE and excludes the key; a forwarding key opens the config and nothing else. An object whose bytes do not hash to the row's digest refused at gkm and at a rotator; a rotation with a missing object skips and later delivers.

##### REPO-M4-01: The ios_extension leg's forwarding list, its module rule and its size budget
- Change: new (od-197-forwarding.md's, amended: the list is the measured closure, the size is measured stripped, and the budget is 6 MiB)
- Milestone: M4
- Repos: sidecar, sdk
- Size: M
- Spec: D-SDK-20, D-SDK-8, D-REPO-4, R-SDK-6, Q-SDK-5, Q-SDK-7, owner decision 197, DESIGN-DETAILS 4.2.3
- Needs: REPO-M0-04: `failsOnRows`; running make-check; SDK-M4-02's descriptor test
- Provides: `check/testdata/ios_extension_leg.txt`, the root and `protocol` files the leg links; `//go:build !ios_extension` on every other root file and, through protocol/Makefile, on `mail.pb.go` and `socket.pb.go`; the leg's file rule and refused-module rule; `make size`'s `ios_extension` row at 6,291,456 B, stripped; sdk's descriptor and import tests on the list
- Files: sidecar/check/legs_test.go, sidecar/check/legrows_test.go, sidecar/check/planted_legs_test.go, sidecar/check/size_test.go, sidecar/check/size_gate_test.go, sidecar/check/settings_test.go, sidecar/check/testdata/ios_extension_leg.txt, sidecar/protocol/Makefile, sidecar/Makefile, sdk/sidecar_ios_extension_test.go, sdk/dependency_boundary_test.go, the root files that gain the tag
- Build: DESIGN-DETAILS 4.2.3. The list is computed, never hand-picked: start from the root files BRIDGE-M8-05 names (before they exist, from config_rows_only.go, config_seal.go, config_head.go, acl_state.go, acl_eval.go, gkm_delivery.go, gkm_keys.go, gkm_api.go, api_client.go, api_routes_core.go, evs_read.go and push_poll.go), build the leg with every other root and `protocol` file replaced by an empty one through `-overlay`, add the file that declares each undefined name, and repeat until it compiles. On 2026-11-10 that is 269 of the leg's 428 root files and 15 of 17 generated `protocol` files. Tag every file outside it `!ios_extension`, joined with `&&` to a constraint it already has. Rules: (1) the leg's root and `protocol` `GoFiles` are a subset of the list, and a file outside it fails naming the fix, which is the tag; (2) the leg's `go list -deps` holds no package of github.com/mjl-/mox, github.com/mjl-/adns, github.com/emersion/go-smtp, go-message or go-imap, github.com/miekg/dns, github.com/mholt/acmez, github.com/letsencrypt/pebble, github.com/modelcontextprotocol/go-sdk, github.com/andybalholm/brotli, gopkg.in/yaml.v3, golang.org/x/text/encoding or golang.org/x/net/html, and none of `net/rpc`, `text/template`, `html/template`; (3) the list may shrink freely and grows only in a commit that edits it. `make size`: the probe keeps connect's surface, `device`'s, `protocol/bridge`'s and, of the root, the exported surface of bridge_forward*.go alone, and both builds take `-ldflags=-s -w`, the flags sdk/build/Makefile ships with; `settings.iosExtensionAddedMaxByteCount` becomes 6,291,456, labeled proposed until question details-4-ios-forwarding-budget is answered. The leg is the same on `gomobile macos/arm64 extension`. Trap: the extension's executable ceiling in sdk/build/check_apple_size.sh moves only on the owner's answer; until then a build over 50 MiB fails there, the closed direction.
- Tests: a planted root file outside the list, a planted `protocol` file, and a planted import of each refused module, each failing with its positive twin; the size verdict at its edge; `TestSizeGateFindsATablePlantedInDevice` against the new limit and a table planted in a listed root file; sdk's descriptor test reading the list.

##### SDK-M8-17: The posture under decision 197: denials, the overdue alarm, the sealed store and the floor
- Change: new (this section's; the delta to SDK-M4-01's landed posture)
- Milestone: M8
- Repos: sidecar
- Size: M
- Spec: D-SDK-13, D-BRIDGE-18, DP1, I-4, owner decisions 185, 187, 189, 197, DESIGN-DETAILS 4.2.5 and 4.3
- Needs: SDK-M4-01: `device.Posture`; BRIDGE-M4-11: enforcement of a `PostureDecision`; TEAM-M2-20
- Provides: `PostureOverlayDelegationRevoke` and `PostureOverlayForwardSupersede`; `PostureDecision.Waiting` and `Overdue`, a report that nothing enforces (QD-621); `PostureSettings.NarrowingOverdueTimeout` (10 min) and `Now`; `device.NewSealedPostureStore(inner, rootKey)`; `PostureSettings.Floor` (`device.PostureFloor{Load, Commit}`); `Posture.SetFork(fork bool)`; `PostureAlarmStoreRolledBack`, `PostureAlarmCompileOverdue`
- Files: sidecar/device/posture.go, sidecar/device/posture_apply.go, sidecar/device/posture_verify.go, sidecar/device/posture_store.go, sidecar/device/posture_seal.go, sidecar/device/posture_seal_test.go, sidecar/device/posture_overlay_test.go, sidecar/device/posture_floor_test.go, sidecar/device/posture_fuzz_test.go
- Build: DESIGN-DETAILS 4.2.5's tier 1. (1) Two overlay kinds: a `SIGNED_DELEGATION_REVOKE` whose signer is standing at the stored rows denies the forwarding key of the Delegation its field 2 names, read by wire, and a `SIGNED_DELEGATION` whose field 7 parses as a `bridge.ForwardScope` naming its own signer denies that sidecar's forwarding key under any other `delegation_id`, both until a state at or past them. (2) An Unsuspend lifts nothing: `postureEffect`'s lift fields go, and the entry only marks a compile wanted. (3) Every entry the posture does not apply as a denial and whose SignedType is in the narrowing set (4.2.5's table) joins `Waiting` with the time it was first seen, persisted in the manifest; once one has waited `NarrowingOverdueTimeout` the decision reports `Overdue` (the oldest waiting entry's position and age, and the next alarm time) and the posture raises `PostureAlarmCompileOverdue` with them, again each `NarrowingOverdueTimeout` while an entry waits past its own, until a state at or past every such entry arrives. The decision is never pending for a waiting entry and `device.Bridge` enforces nothing by `Overdue`: the last compiled state stays in force (question details-4-compile-deadline, option 2; QD-621). The clock is `PostureSettings.Now`, read only for this. (4) `NewSealedPostureStore` wraps any `PostureStore`: each record is `UFS1` || a 16 B file id || 64 KiB chunks sealed with AES-256-GCM under HKDF-SHA256(root key, file id, "urnetwork-sidecar-v1/forward-store" || name), nonce u32be(0) || u64be(chunk index), AAD the name, the file id, the index and a final-chunk byte; std only, since `device` may not import x/crypto. (5) The floor: after each commit whose pin rose the posture calls `Floor.Commit(n, chain)`; at load a manifest whose pin is below `Floor.Load()`, or equal with another chain, is pending with `PostureAlarmStoreRolledBack`, and the posture stays pending until its pin reaches the floor on the floor's chain. (6) `SetState` drops a state whose pin is below the state in force and keeps every overlay and waiting entry above the new state's pin. (7) `SetFork(true)`, persisted in the manifest, makes the decision pending until `SetFork(false)`: the app's sidecar role, a full reader, found a base that does not compile from its head. Trap: the overlay never opens: no kind added here may raise reach, and `FuzzPostureNeverOpens` holds it.
- Tests: each new kind with its positive twin and a wrong signer; an Unsuspend after an overlay Suspend leaves the subject denied until the next state; an unverifiable SidecarRevoke leaves the decision as it was and the state in force, raises the alarm after 10 min on a fake clock and again at 20, across a restart, and clears at a state; a lower state refused; a state at pin p keeps the overlay above p (Fwd.tla's StateDropsOverlay and LowerStateAccepted on real code); sealed records refuse a flipped byte, a truncated file, a swapped chunk and a record moved to another name; a rolled-back store is pending and alarms, then recovers at the floor; `FuzzPostureNeverOpens` over generated logs.

##### BRIDGE-M8-04: Forwarding-key delegations at hosts and senders
- Change: new (od-197-forwarding.md's, with the overlay's enforcement)
- Milestone: M8
- Repos: sidecar
- Size: M
- Spec: D-BRIDGE-17, D-BRIDGE-5, D-SDK-32, I-3, I-4, FS-38, owner decision 197, DESIGN-DETAILS 4.2.5
- Needs: BRIDGE-M4-10: `bridge.VerifyWindowDelegation`; BRIDGE-M4-11; BRIDGE-M4-12: the link's destination check; BRIDGE-M4-16: `CompileBridgeState`; TEAM-M2-20; TEAM-M8-01; SDK-M8-17
- Provides: `bridge.VerifyWindowDelegation`'s forwarding path; the compiler filling `BridgeIdentity.forward_delegation_id` and `forward_public_key` from each subject's live forwarding Delegation; `BridgeEgressPolicy` refusing a principal whose forwarding key the overlay denies; for an app host, `BridgeRuleLink`'s target client and pinned key from its forwarding Delegation's host client
- Files: sidecar/protocol/bridge/delegation.go, sidecar/protocol/bridge/delegation_test.go, sidecar/testdata/bridge/delegation/, sidecar/device/bridge_principal.go, sidecar/device/bridge_principal_test.go, sidecar/device/bridge_state.go, sidecar/device/bridge_state_test.go, sidecar/device/bridge_link.go, sidecar/device/bridge_link_test.go, sidecar/bridge_compile.go, sidecar/bridge_compile_test.go
- Build: §17.9's verify row. A `signer_id` of 32 bytes is a `delegation_id` and `key_id` the SHA-256 of its public key: the delegation verifies only under the subject's `BridgeIdentity.forward_public_key` with that `forward_delegation_id`, the subject named by the delegation equal to the identity's. A 16-byte `signer_id` keeps the identity-key path. Paths by length, never by trying keys (QD-093). The principal carries which key admitted it; `ResolveEgress`'s per-flow recheck denies a forwarding-key principal while the overlay holds a `DelegationRevoke` of its id or a supersession of its sidecar, and `Bridge.Revoke` closes its flows after the policy swap (D-BRIDGE-21's order). A principal the identity key admitted is untouched by either. The target row: a link to an app host checks `destination_client_public_key` against the host client key the rules pin, never `GET /sidecar/identity`, which names S's own client. Trap: the compiler writes the forwarding fields only for a Delegation live at the state, so a superseded or revoked one leaves at the next compile.
- Tests: vectors in testdata/bridge/delegation/ for the forwarding path; each mismatch alone (another sidecar's forwarding key, a superseded one, a revoked one, a ShareCert type, a 32-byte signer with a 16-byte key id) refused with its positive twin; an overlay DelegationRevoke closes exactly the flows its key admitted, an identity-key principal of the same subject surviving; an app host's link refusing a substituted host key; zero upstream sockets on an operator-minted contract carrying a forged forwarding delegation, as FS-38 counts them.

##### BRIDGE-M8-05: The Forwarder: following, the transient compile and signing in a VPN component
- Change: new (od-197-forwarding.md's, rewritten to DESIGN-DETAILS 4.2.4 and 4.2.5)
- Milestone: M8
- Repos: sidecar
- Size: L
- Spec: D-SDK-13, D-SDK-20, D-SDK-32, D-BRIDGE-18, R-BRIDGE-3, I-4, I-12, owner decision 197, DESIGN-DETAILS 4.2.4, 4.2.5, 4.2.6
- Needs: BRIDGE-M4-16; BRIDGE-M8-04; TEAM-M2-11: the rows-only `ConfigLog`; TEAM-M2-08: `OpenConfigBody`, `NewConfigHead`; ACL-M2-02: `NewAclState`; KEYS-M2-20: `ParseGkmDelivery`, `OpenGkmDelivery`, `OpenGkmLadder`; KEYS-M8-01; TEAM-M8-01; TEAM-M8-02; EVS1's `EvsRepo.ReadHead` on the config repo; REPO-M4-01: the leg's list
- Provides: `Forwarder` (`NewForwarder(ctx, *ForwarderArgs)`), with `ReceiveHint(position)`, `Witness(pin, fork)`, `Status()`, `Close()`; `ForwarderSettings` and `DefaultForwarderSettings(hostClass)`; `ForwarderStore` and `ForwarderKeys`, the interfaces sdk implements; `ForwardingSigner.SignWindowDelegation`; `ForwarderSink`, which `device.Bridge` satisfies through sdk (`SetPending`, `SetState(state, log)`, `ApplyDeltas(log)`, `SetFork(fork)`, `Decision()`); `bridge_alarm` reasons `compile_over_budget`, `compile_deferred`, `config_key_waiting`, `forward_client_lapsed`, `narrowing_overdue` (the posture's `PostureAlarmCompileOverdue`, with the entry's position and age; the Forwarder's timer wakes at the decision's next alarm time)
- Files: sidecar/bridge_forward.go, sidecar/bridge_forward_follow.go, sidecar/bridge_forward_compile.go, sidecar/bridge_forward_keys.go, sidecar/bridge_forward_sign.go, sidecar/bridge_forward_test.go, sidecar/bridge_forward_follow_test.go, sidecar/bridge_forward_compile_test.go, sidecar/bridge_forward_keys_test.go, sidecar/bridge_forward_sign_test.go
- Build: DESIGN-DETAILS 4.2.5's `Follow` and `Compile`, in root files on REPO-M4-01's list, naming no type outside it. No state stays in memory between compiles but the pin, the timers and the settings: `Follow` hands each page to the sink's `ApplyDeltas` and schedules a compile when 4.2.5's table says; `Compile` runs the admission rule (estimate = 5 x rows_byte_count + 2 x head byte count + the newest base's tail bytes + 1 MiB, against `CompileMemoryMaxByteCount`, and with the process's heap in use against `CompileHeapCeilingByteCount`), restores a rows-only `ConfigLog` from the store at its newest base and applies the entries after it through `ApplyRun` 256 at a time, opens the generations it needs by DelegationWrap under the forwarding reader key, reads a head it has not cached, builds `AclState`, calls `CompileBridgeState` for S, hands the state with its log run to the sink, commits, drops every reference and, on mobile host classes, calls `debug.FreeOSMemory`. It is single-flight per network, coalesces for `CompileDelay` and never starts within `CompileMinInterval` of the last. It never signs a statement and holds no identity key. The signer signs only its sidecar's delegations: subject S, `signer_id` the Delegation's id, `key_id` the SHA-256 of the forwarding public key, `not_after_ms` at most the window client's `strict_exp`; on a share link the share's current ShareSigner from the compiled state while its cert is unexpired. `Witness` fetches up to the app's pin and raises `head_alarm` on a pin off its chain; `fork = true` calls the sink's `SetFork`, which forces pending until a later witness clears it. Trap: an error anywhere in a compile changes nothing: the sink is called only with a whole state. Trap: no import of an `mls_`, `mail_`, `search_` or any file outside the leg's list, which `make check` fails.
- Tests: on `sidecartest`'s fakes, with no sidecar role running: a new grant and a revocation reach the sink within §8.9's targets; a pure revocation reaches it with no compile; an Unsuspend reaches it only by a compile; a config rotation's DelegationWrap opens the new generation and a missing one alarms `config_key_waiting` while older bodies still compile; a superseded key set stops opening after the next rotation; the signer refuses another subject; a share's new signer re-signs live links; `Witness` reports a pin off its chain; the admission rule refuses a 5,000-device fixture at the iOS settings and compiles a 3,000-device one, heap sampled; two hints during a compile make one more compile; a kill at each step of `Compile` leaves the store loadable and the state unchanged.

##### BRIDGE-M8-06: Forwarding's setup in the sidecar role
- Change: new (od-197-forwarding.md's, with the steps' order, their record and the key set)
- Milestone: M8
- Repos: sidecar
- Size: M
- Spec: D-SDK-32, D-TEAM-33, D-CORE-13, I-6, I-7, I-8, owner decision 197, DESIGN-DETAILS 4.2.6
- Needs: TEAM-M8-01; TEAM-M8-02; KEYS-M8-01; CORE-M8-01: child mints; CORE-M1-10: `Daemon.RegisterMethod`; TEAM-M2-10: `ConfigClient.WaitFor`
- Provides: `Sidecar.SetUpForwarding(ctx, networkId, *bridge.ForwardingKeys) (*bridge.ForwardingHandOff, error)`; `Sidecar.ForwardingSetupDue(networkId) ForwardingSetupReason`; `Sidecar.ConfirmForwardingSetup(networkId)`; `Sidecar.ForwardingWitness(networkId)`; the control methods `bridge.forwarding.setup` and `bridge.forwarding.witness` for a paired remote-mode app (proposed names)
- Files: sidecar/bridge_forward_setup.go, sidecar/bridge_forward_setup_test.go, sidecar/daemon_bridge.go, sidecar/daemon_bridge_test.go
- Build: DESIGN-DETAILS 4.2.6's setup, six steps, each idempotent, with a record `forward/<network_id>/setup` in the sidecar's store written before step 1 and after each step: (1) sign the Delegation for the keys given, `forward` naming S and, where S's client is the device client's child, that client and its key, and record the Signed bytes; (2) file those bytes through `POST /network/config/delta` and `WaitFor` their position, a repeat finding a copy already in the log by its id, and a 409 at the tip re-signing at the new pin; (3) `UploadDelegationKey`; (4) write the late DelegationWrap of the config's current generation; (5) mint F with `forward_only`, the component's `client_public_key` and S's DPoP proof; (6) return the hand-off. A repeat with the record's `key_set_id` resumes at the first step not done; a repeat with another supersedes. `ForwardingSetupDue` answers `new_client_generation`, `ninety_days`, `none_live` or `foreign_revocation`; the last runs only after `ConfirmForwardingSetup`, which an app's UI calls and MCP cannot. From control mode only for the paired app (§5.8). Trap: the hand-off carries no key of S, and F's token is never logged or returned to any other caller (I-7).
- Tests: setup at enrollment, re-enrollment and pairing; a kill after each step resumes to one Delegation and one F; the 90-day rotation and no other; a foreign revocation held until confirmed, and S's own revocation not held; an MCP or unpaired control caller refused; the hand-off's contents, and a log scan finding no token.

##### BRIDGE-M8-07: M8-out: forwarding's cases end to end
- Change: new (od-197-forwarding.md's, with Fwd.tla's twins as schedules)
- Milestone: M8
- Repos: sidecar, server, sdk
- Size: M
- Spec: FS-38, FI-11, D-BRIDGE-17, D-SDK-32, I-3, I-4, owner decision 197, DESIGN-DETAILS 4.6
- Needs: BRIDGE-M8-04; BRIDGE-M8-05; BRIDGE-M8-06; SDK-M8-16; SDK-M8-17; TEAM-M8-01; TEAM-M8-02; KEYS-M8-01; BRIDGE-M4-22: `sidecartest.BridgeNet`, `Net.MintContract`
- Provides: §22.5's §17 row's forwarding cases at M8 on T2 and T3; §23.6's M8 row for forwarding
- Files: sidecar/sidecartest/fault/fs_bridge_forwarding_m8_test.go, sidecar/sidecartest/bridge_net.go, server/controller/connect_bridge_forwarding_test.go
- Build: DESIGN-DETAILS 4.6's schedule rows on FS-38's operator-minted contracts: a forwarding-key delegation admitted, every refused one opening zero upstream sockets; with the app's sidecar stopped, a new grant and a revocation reach the host in §8.9's targets; a DelegationRevoke racing a compile; a supersession racing a contract; a compile finishing below a newer state; `forward_only` getting the config's `r` alone. Each of Fwd.tla's twins is one schedule that must hold on real code.
- Tests: the cases above on T2 and T3, reported by tier; any blocked by an open question listed, never skipped silently.

##### SDK-M8-16: The VPN component's forwarding host in DeviceLocal
- Change: new (od-197-forwarding.md's, with the key sets, the floor and the per-class settings; the RPC methods move to SDK-M8-07)
- Milestone: M8
- Repos: sdk
- Size: L
- Spec: R-SDK-3, R-SDK-6, D-SDK-13, D-SDK-20, D-SDK-32, DP1, I-3, owner decision 197, DESIGN-DETAILS 4.2.2, 4.2.4, 4.2.6
- Needs: SDK-M4-01; SDK-M4-02; SDK-M8-17; BRIDGE-M8-05; PROTO-M8-01: `team` hints to `acl_enforcing` device clients
- Provides: `SidecarForwardKeyStore` (app-implemented, gobind-safe, statuses as `SidecarKeyStore`'s); `deviceLocalForwarding`, one per network, with `keys(networkId)`, `handOff(*bridge.ForwardingHandOff)`, `witness(networkId, pin, fork)`; the forwarding store, sealed, in the VPN component's own container; F's refresh; D's `team` hints and the long-poll feeding the `Forwarder`; `deviceLocalBridgeOwner` holding one device role per network; the status mirror's forwarding fields
- Files: sdk/device_sidecar_forward.go, sdk/device_sidecar_forward_store.go, sdk/device_sidecar_forward_keys.go, sdk/device_sidecar.go, sdk/device_sidecar_store.go, sdk/device_sidecar_forward_test.go, sdk/device_sidecar_forward_store_test.go, sdk/device_sidecar_forward_keys_test.go
- Build: DESIGN-DETAILS 4.2.6, the VPN component's side. `keys` generates a key set (the forwarding seed, the X-Wing seed, F's ClientKey seed) under a fresh `key_set_id` into the `next` slot and returns public halves only; `handOff` checks the Signed Delegation names exactly those public keys and S, stores the token, and promotes `next` to `current` only once the component's own posture holds a state at or past `delegation_at` that shows that Delegation live, deleting the old set then. The store is 4.2.2's layout: seeds, the root key, the token and the floor through `SidecarForwardKeyStore` (§5.9's table), everything else in files under `device.NewSealedPostureStore`, outside any app group. Keys are generated only at a setup; a store state other than Present leaves forwarding pending, never resets it. Settings by host class from `DefaultForwarderSettings`: iOS and macOS extensions `CompileMemoryMaxByteCount` 10 MiB and `CompileHeapCeilingByteCount` 30 MiB, Android 16 MiB and none, desktop services 64 MiB and none. Forwarding runs whenever the VPN component runs: no app setting stops it, and `EnableBridge` is a release gate only (§17.16). One `Forwarder`, posture and forwarding client per network the hand-offs name; the router takes each network's block and, where two collide, the first-joined network's (§17.4); hosting runs only in the device client's network. F is refreshed by its own DPoP proofs at 40 to 50% of its `strict_exp`; an expired token at start makes the posture pending with `forward_client_lapsed`. Trap: on Android the service shares the app's process, so keep the forwarding store's keys and files apart from the sidecar role's, and say in the doc that the process boundary is app work (§18.15).
- Tests: keys never cross, by a capture of every call out of the package; a rule change and a revocation applied with the app's sidecar stopped; two networks forwarding at once, each on its own posture, with hosting refused outside the device client's; F refreshed by its own proofs, and after 7 days unrefreshed pending until a new hand-off; a hand-off naming other keys refused; `next` promoted only at the live state, and a kill between hand-off and promotion keeps signing with `current`; the posture restored before the first packet from the sealed store; a corrupt store pending, never legacy; a rolled-back store pending; DP1's rows on the forwarding path.

#### Changed tasks

##### SDK-M4-01: The posture machine in device/
- Change: changed (drafted). Its code stands; its delta is SDK-M8-17. Spec gains owner decision 197 and DESIGN-DETAILS 4.2.5.
- Build: One machine for the forwarding role, fed in process by the VPN component's own `Forwarder`: `Posture.SetState(state, log)` keeps the argument it was built with, which answers question sdk-m4-01-state-proof with no channel (4.2.5). `Pending` arrives at forwarding's setup with `sidecar_id`, the identity key (QD-211) and the forwarding Delegation's id. Doc comments naming the keyless device role and a sidecar role's states change to the forwarding role and its own compile.

##### SDK-M4-02: The deviceBridge seam in sdk
- Change: changed (partial)
- Needs: adds REPO-M4-01
- Build: As planned, with three changes. `sdkPostureStore` moves out of the NetworkSpace's `storagePath` where that is the app group, into the VPN component's own container, and is wrapped by `device.NewSealedPostureStore` (SDK-M8-16 supplies the root key; until M8 the M4 seam stays dark behind `EnableBridge` and writes nothing). `sdk/sidecar_ios_extension_test.go`'s "only protocol/bridge's descriptors" becomes REPO-M4-01's list. "make size passing with margin" means REPO-M4-01's stripped row: the seam with `device` and `protocol/bridge` adds 1,083,256 B stripped on 2026-11-10 against 6,291,456 B, which closes question sdk-m4-02-make-size-over on its option 2 with the limit this section proposes. `EnableBridge` stays a release gate, never a setting.

##### SDK-M6-01: The sdk.Sidecar shell
- Change: changed (drafted)
- Build: App hosts' `Components` never include "bridge": `NewSidecarLocal` and `NewSidecarRemote` refuse it with a typed error, since forwarding is the VPN component's.

##### SDK-M8-01: Host services: the Api session, EnrollWithDevice, Unlock and state
- Change: changed (open)
- Build: As planned, and `applySidecarHostClass` runs Android's sidecar role only while the app is open, OS windows and wakes aside, as iOS's. Forwarding's setup after enrollment is SDK-M8-07's wiring, so this task gains no need.
- Tests: adds an Android host class that starts no background sidecar while the VPN runs.

##### SDK-M8-02: The remote backend: NewSidecarRemote over §5.8's control mode
- Change: changed (open)
- Needs: adds BRIDGE-M8-06
- Build: As planned, and it relays forwarding's setup and witness to the daemon over `bridge.forwarding.setup` and `bridge.forwarding.witness` for a paired desktop app, carrying `bridge.ForwardingKeys` out and `bridge.ForwardingHandOff` back, never a key.

##### SDK-M8-04: SidecarMail: aliases, coverage, the receiver and burners
- Change: changed (open)
- Build: As planned, but `SetReceiverEnabled` files or retires a remote-mode app's daemon's `IndexerSet` for mail, and local mode answers refused, since app hosts receive only while open (owner decision 197).
- Tests: drop the Android receiver case; `TestReceiverEnableFilesIndexerSet` on the remote backend.

##### SDK-M8-07: The device channel: the hand-off, status, routes and acl_enforcing
- Change: changed (open; retitled). Dropped: `rpcBridgeStateSink`, `DeviceLocalRpc.SetBridgeState` and its chunks (reading 11), the control method `bridge.state`, `sidecar/daemon_bridge.go`'s state relay.
- Milestone: M8
- Repos: sdk, sidecar
- Size: M
- Spec: R-SDK-3, D-SDK-1, D-SDK-3, D-SDK-13, D-SDK-32, D-BRIDGE-12, DP1, Q-SDK-2, I-4, I-7, I-10, owner decision 197
- Needs: SDK-M4-01; SDK-M4-02; SDK-M8-01; SDK-M8-02; SDK-M8-16; BRIDGE-M8-06; BRIDGE-M4-13: `Bridge.Routes`, `Bridge.SetLocalAddresses`; TEAM-M1-04: `acl_enforcing` on `POST /network/auth-client`; PROTO-M8-01; CORE-M1-10: `Daemon.RegisterMethod`
- Provides: `DeviceLocalRpc.ForwardingKeys`, `DeviceLocalRpc.ForwardingHandOff`, `DeviceLocalRpc.ForwardingWitness`; `DeviceLocalRpc.GetBridgeStatus`; `DeviceRemoteRpc.BridgeStatusChanged`; `Device.GetBridgeStatus`; `Device.AddBridgeStatusChangeListener`; `BridgeStatus` with the forwarding fields; `DeviceLocal.GetBridgeRoutes`; `BridgeRouteList`; `DeviceLocal.SetBridgeLocalAddresses`; the status mirror; `AuthNetworkClientArgs.AclEnforcing`; the `acl_enforcing` mint; `sdk/sidecar_forward_setup.go`'s run of setup after `EnrollWithDevice` and at each `ForwardingSetupDue`; the bound `Sidecar.ConfirmForwardingSetup(networkId)` and the `bridge_alarm` reason `forwarding_revoked` that prompts it
- Files: sdk/device_sidecar_channel.go, sdk/device_sidecar_routes.go, sdk/device_rpc.go, sdk/device_rpc_methods.go, sdk/device.go, sdk/device_local.go, sdk/api.go, sdk/sidecar_forward_setup.go, sdk/device_sidecar_channel_test.go, sdk/device_rpc_mirror_test.go, sdk/sidecar_forward_setup_test.go
- Build: §18.6's Setup and Mirror. Three additive RPC methods carry setup: `ForwardingKeys(networkId)` returns the component's public halves, `ForwardingHandOff(bytes)` delivers the hand-off, `ForwardingWitness(networkId, pin, fork)` the app's witnessed pin; in process on Android, over the device RPC to the Apple extensions, and from `ur daemon` through the paired desktop app (SDK-M8-02). Each is listed in its method table, an older peer answers unknown, and `DeviceRpcVersion` stays 3. No state, delegation or key crosses. `sidecar_forward_setup.go` (`!ios_extension`) runs `Sidecar.SetUpForwarding` after `EnrollWithDevice`, at each `ForwardingSetupDue` when the sidecar role starts, and after the person's `ConfirmForwardingSetup`, which it offers by raising `forwarding_revoked` when `ForwardingSetupDue` answers `foreign_revocation`; it sends `ForwardingWitness` at each witnessed pin and at a fork. `GetBridgeRoutes`, `SetBridgeLocalAddresses`, the status mirror and the `acl_enforcing` mint are as planned, the mint now after the forwarding role leaves legacy. D's `team` follower is SDK-M8-16's and feeds the `Forwarder`. Hosted devices refuse all of it.
- Tests: `TestDeviceRpcMethodTablesServeEveryMethod`; `TestDeviceRpcVersionStaysThree`; the mirror's T4 rows; a capture of the three methods' payloads holding no private key; `TestHandOffQueuedWhileDisconnected`; `TestSetupRunsAfterEnrollment`; `TestForeignRevocationWaitsForConfirm`; `TestDesktopPathThroughControl` on a fake daemon; `TestUnsignedResponseOverRpcIgnored` (DP1).

##### SDK-M8-08: BridgeHost in DeviceLocal on the forwarding client
- Change: changed (open; retitled). Dropped: `DeviceRemoteRpc.SignWindowDelegation`, `DeviceLocalRpc.SetWindowDelegation`, `DeviceLocalRpc.ResignShares`, the control method `bridge.delegation.sign`, and the keyless requester half of `Sidecar.SignWindowDelegation`.
- Milestone: M8
- Repos: sdk
- Size: M
- Spec: D-SDK-3, D-SDK-13, D-SDK-32, I-3, I-5, R-CTX-5
- Needs: SDK-M8-16; BRIDGE-M8-05: `ForwardingSigner`; BRIDGE-M4-12: `device.BridgeLinkMultiClientSettings`, `device.NewBridgeLinkGenerator`; BRIDGE-M4-06: `device.BridgeHost`
- Provides: `DeviceLocal.NewBridgeLink`
- Files: sdk/device_sidecar_host.go, sdk/device_sidecar_host_test.go
- Build: `DeviceLocal.NewBridgeLink` implements `device.BridgeHost` on `device.BridgeLinkMultiClientSettings` and `device.NewBridgeLinkGenerator`. The generator's `ClientCredentials` are the forwarding client F's for the link's network, so each window client is F's child, inherits `forward_only` and `strict_exp`, and is sealed by C13 as S's client (D-ACL-3). `sign` is the network's `ForwardingSigner.SignWindowDelegation`, in process, so no link waits on the app; when a compile brings a new `BridgeShareSigner` the host calls `sign` again for each live window client of that share (§17.10). With no current key set, or F lapsed, `sign` errors and the link fails closed. This replaces QD-184's mint over the device channel on app hosts.
- Tests: `TestNewBridgeLinkSettings`; a window client minted under F seals S's client as subject; a sign error opens zero contracts; `TestNotAfterCapped`; `TestExpiredShareCertRefused`; a new share signer re-signs live links; the app's process stopped throughout.

##### SDK-M8-15: T4's surrogate cells and app-host suites
- Change: changed (open)
- Needs: SDK-M8-07; SDK-M8-08; SDK-M8-16; CORE-M8-03; SDK-M8-06
- Build: As planned, with forwarding's cells: on the ios32 surrogate a forwarding role compiles a 3,000-device team's config with its sampled heap peak within `CompileMemoryMaxByteCount` and refuses a 5,000-device one with `compile_over_budget`, its state kept and nothing pending (QD-620, QD-621; the cell becomes "compiles a 5,000-device one within the cap" when the review phase's storage-backed compile lands, 4.2.4); its steady heap after `FreeOSMemory` within 4 MiB at 5,000 identities; the leg's start heap over the baseline's reported (625,296 B on 2026-11-10's probe). The Android cell runs no background sidecar.

##### SDK-M10-02: Host classes, conditions, windows and foreground
- Change: changed (open)
- Build: As planned, but Android's class matches iOS's: foreground, plus WorkManager's charging and unmetered windows as iOS's BGProcessingTask; no VPN-held background (owner decision 197).

##### BRIDGE-M4-16: The compiler: BridgeState from verified config
- Change: changed (open; held under problem 12, whose section owns its algorithm)
- Build: Three constraints from this section. It reads the config only through `BridgeConfigView`, which a daemon backs with its full reader and a VPN component with the Forwarder's rows-only `ConfigLog`, opened head and opened bodies, so it never calls `ConfigClient`. It fills `BridgeIdentity.forward_delegation_id` and `forward_public_key` from each subject's live forwarding Delegation, and an app host's link target and pinned key from that Delegation's host client. Its files are on REPO-M4-01's list and it allocates nothing proportional to the network beyond its output and one pass over the view.

##### BRIDGE-M4-17: The bridge component: engine, delegations and the host's NAT
- Change: changed (open; held under problem 12)
- Build: On app hosts the component is not built: `Components` refuse "bridge" (SDK-M6-01), no `BridgeStateSink` feeds a device role over a channel, and no keyless requester's delegation is signed. `SetDeviceRole` stays for `cli/`'s `ur tun`, and `Sidecar.SignWindowDelegation` serves the daemon's own links.

##### BRIDGE-M8-01: App-device hosts after C16
- Change: changed (open)
- Needs: BRIDGE-M4-05; BRIDGE-M4-10; BRIDGE-M4-21; BRIDGE-M8-04; SDK-M8-16
- Build: As planned, in D's network only. Senders' target check uses the host client key S's forwarding Delegation names (BRIDGE-M8-04). The device role's states come from its own `Forwarder`. Whether setup files the device's `BridgeAddress` stays §17.4's on demand (Q-BRIDGE-8).

##### BRIDGE-M8-02: Link gates and egress on apps
- Change: changed (open; retitled from "Keyless window clients, link gates and egress on apps"). Dropped: the sidecar role's mint over the device channel (QD-184's path), `sdk/device_sidecar_mint.go`, `sidecar/bridge_mint.go` and their tests.
- Needs: BRIDGE-M4-12; BRIDGE-M4-14; SDK-M8-08; BRIDGE-M8-05
- Provides: `LinkCountMax` per platform; §17.9's egress spec on app devices
- Files: sdk/device_sidecar_egress.go, sdk/device_sidecar_egress_test.go
- Build: Links on apps are SDK-M8-08's. This task sets `LinkCountMax` per platform, 0 on iOS until §22.9 measures one (owner decision 100), and builds egress on apps as planned: a subject's default route goes to an approved exit, or nowhere, through `NetworkPeer` with `PostQuantumEncryption`, default off.
- Tests: `LinkCountMax` 0 builds nothing and rejects. Egress `none` sends nothing; `exits` sends only to an exit.

##### BRIDGE-M8-03: §22.9's bridge cells: link memory, forwarding's compile, CGNAT and overlay ICE harnesses
- Change: changed (open)
- Needs: BRIDGE-M4-08; BRIDGE-M4-12; BRIDGE-M8-01; BRIDGE-M8-02; BRIDGE-M8-05
- Build: As planned, and the memory cell also samples a forwarding compile beside one link on the ios32 surrogate, reporting the heap peak against 4.4's table, and reruns 4.4's rows fixture so the 5x factor is re-measured whenever `SidecarRow` or `AclRows` change.

#### Changed outside BRIDGE and SDK, carried from od-197-forwarding.md

| Task | Change |
|---|---|
| BRIDGE-M4-10, BRIDGE-M4-11, BRIDGE-M4-12 (drafted) | No change at M4; extended by BRIDGE-M8-04 and SDK-M8-17. On apps the generator's parent is F (SDK-M8-08). |
| BRIDGE-M4-06 (drafted) | Comments only: the delegation signer is the forwarding signer; `bridge.proto`'s comments on a sidecar role's view for its device role change. |
| KEYS-M2-03, KEYS-M2-28 | Extended by KEYS-M8-01: the forwarding kind and identity; supersession without a shrink and its revocation's REMOVE rotation join FS-18. |
| TEAM-M1-01, TEAM-M1-02, TEAM-M1-04, TEAM-M1-06 | Extended by TEAM-M8-02; `forward_only` joins the marks a child inherits. |
| TEAM-M2-01, TEAM-M2-04 | Extended by TEAM-M2-20's fields; the agent rules exclude a Delegation with `forward` set. |
| MAIL-M8-04, MAIL-M8-05, MAIL-M8-10 | No app is a mail indexer; an app's wake only resyncs; the indexer paths are the desktop daemon, a NAS or a VPS. |
| PROTO-M8-01 | No change: D's `team` hints feed the forwarding role's follower. |

#### Unchanged

BRIDGE-M2-01, BRIDGE-M4-15, BRIDGE-M4-18, BRIDGE-M4-19, BRIDGE-M4-20, BRIDGE-M4-22, BRIDGE-M6-05, BRIDGE-M6-06, BRIDGE-M6-07, BRIDGE-M6-08, SDK-M3-01, SDK-M4-04, SDK-M4-05, SDK-M4-06, SDK-M4-08, SDK-M4-09, SDK-M6-02, SDK-M6-03, SDK-M8-03, SDK-M8-05, SDK-M8-06, SDK-M8-10, SDK-M8-12, SDK-M8-14, SDK-M9-01, SDK-M10-01, SDK-M10-03, SDK-M10-04, SDK-M10-05, SDK-M10-06: unchanged; each builds as its plan entry says, with the note 4.7 gives it.

#### Dropped

None whole. The dropped halves are in SDK-M8-07, SDK-M8-08 and BRIDGE-M8-02 above. RESOLUTIONS' plan-BRIDGE-keyless-window-parent (QD-184) and plan-SDK-small-readings #11 (QD-559) no longer apply on app hosts.

#### Order and lanes

The core lane takes TEAM-M2-20 (before M2's freeze), TEAM-M8-01, TEAM-M8-02 and KEYS-M8-01; the ops lane takes REPO-M4-01 (it can start now), SDK-M8-17, BRIDGE-M8-04 to BRIDGE-M8-07, SDK-M8-16, SDK-M8-07 and SDK-M8-08; the edge lane takes MAIL's three changes. Longest chain: TEAM-M2-20 -> TEAM-M8-01 -> KEYS-M8-01 -> BRIDGE-M8-05 -> SDK-M8-16 -> SDK-M8-07 -> SDK-M8-15.

#### Notes for the held tasks

**Landed code that must change** (file, then the task that changes it):

```text
sidecar/protocol/bridge/auth.proto, bridge.proto, protocol/config.proto and their .pb.go   4.2.2's fields (TEAM-M2-20)
sidecar/device/posture.go, posture_apply.go, posture_verify.go   two overlay kinds; no lift on Unsuspend; Waiting
                               and the Overdue report with its alarm, never pending (QD-621); the lower-state
                               rule; the floor; doc comments naming the keyless role (SDK-M8-17)
sidecar/device/posture_store.go   NewFilePostureStore stays the inner store; NewSealedPostureStore wraps it (SDK-M8-17)
sidecar/device/bridge_principal.go, bridge_state.go, bridge_link.go   the 32-byte signer path; the overlay's new
                               kinds enforced per flow; an app host's pinned key (BRIDGE-M8-04)
sidecar/protocol/bridge/delegation.go   VerifyWindowDelegation's forwarding path (BRIDGE-M8-04)
sidecar/device/bridge.go, bridge_settings.go, bridge_host.go, bridge_rules.go, doc.go   comments: the forwarding
                               signer and the component's own compile, not §18.6's channel
sidecar/check/legs_test.go, legrows_test.go, size_test.go, size_gate_test.go, settings_test.go, Makefile   the leg's
                               rule and row (REPO-M4-01); 159 root files and two generated ones gain the tag
sidecar/config_delegation.go   the agent rules exclude a Delegation with forward set (TEAM-M8-01)
sidecar/gkm_holders.go, gkm_api.go, gkm_paths.go, gkmservice/wraps.go, reconciler.go   kind 5 and the key object
                               (KEYS-M8-01)
sdk/device_sidecar.go          deviceLocalBridgeOwner holds one device role per network, not one (SDK-M8-16)
sdk/device_sidecar_store.go    its directory leaves any app group; wrapped by the sealed store (SDK-M4-02, SDK-M8-16)
sdk/sidecar_ios_extension_test.go, dependency_boundary_test.go   the leg's list (REPO-M4-01)
sdk/sidecar.go, sidecar_types.go   refuse "bridge" in an app's Components (SDK-M6-01)
sdk/build/APPLE_EXTENSION_MEMORY_BUDGET.md   the device-role table gains this section's rows when the leg lands
```

No landed code ran a sidecar feature other than forwarding in a VPN component, and none ran Android's mail, sockets, search or evs in the background.

**BRIDGE-M2-01 (statements).** Unchanged, and no longer waiting: bridge statements are ordinary rule-table statements judged at id level everywhere, which is what lets the Forwarder's rows-only judge run them. Two things to hold to: the id-level half must not need a config key (the leg's judge may lack a generation, 4.2.5 step 2), and an entry held pending for its body keeps its id-level effect. The forwarding row is TEAM-M8-01's rule, not this table's.

**BRIDGE-M4-15 (address plan), BRIDGE-M4-18 (`ur tun` on Linux), BRIDGE-M4-19 (filings), BRIDGE-M4-20 (`ur bridge`).** Unchanged: CLI hosts have no forwarding role, and the daemon runs the bridge under its identity key. In -15 and -19 nothing files a `BridgeAddress` at an app's setup (Q-BRIDGE-8 stays on demand). In -19 and -20, `block`, `egress`, `invite` and every filing stay sidecar-role acts: the forwarding key signs no statement, so an app's filings come from the app's sidecar role while it is open.

**BRIDGE-M4-22 (M4-out).** Unchanged. FS-38's sender and host rows run on identity-key delegations at M4; the forwarding-key rows are BRIDGE-M8-07's. `sidecartest.BridgeNet` should take the delegation's signer as a parameter now, so M8 adds a signer rather than a second harness.

**BRIDGE-M6-05, -06, -07, -08 (shares, `ur tun` on macOS and Windows, reach receipts, M6-out).** Unchanged. On an app, a share link's delegation is signed in the VPN component with the share's current `BridgeShareSigner`, which the compile reads from the head into the state it hands the posture, so -05's host side sees the same `ShareCert`-signed delegations whoever built the link. The ShareKey itself never enters a VPN component: `BridgeShareSigner` files are re-certified by the ShareKey holder's sidecar role (§17.9), which an app runs only while open, so a share whose only holder is a phone can lapse after 7 days closed; -07's receipts are written by the sidecar role and coalesce what the component's status mirror counted.

**BRIDGE-M8-01, -02, -03.** Changed, as listed.

**SDK-M3-01 (credential rules).** Unchanged. One addition to its doc: F's token lives only in `SidecarForwardKeyStore`, never in `.auth_state`.

**SDK-M4-04, -05, -06, -08, -09 (the page Worker, the key-origin frame, sidecar.ur.io, FS-37, browser conformance) and SDK-M6-02 (console operations).** Unchanged and untouched by forwarding: the page Worker is the `sidecar_http` leg, which links no connect and no bridge, so nothing in them depends on where forwarding runs.

**SDK-M6-03 (SidecarDirectory, SignEdgeLogin).** Unchanged.

**SDK-M8-01, -02, -04, -07, -08, -15.** Changed, as listed. The order among them: SDK-M8-17, then SDK-M8-16, then SDK-M8-07 and SDK-M8-08.

**SDK-M8-03 (SidecarEvs, SidecarSockets), SDK-M8-05 (SidecarApprovals), SDK-M8-06 (binding gates).** Unchanged. -05's device list shows one device per app, never a second entry for its forwarding Delegation, and its revocation plan names the forwarding Delegation among what a device's revocation ends. -06's export tables gain `SidecarForwardKeyStore` and one bound call, `Sidecar.ConfirmForwardingSetup`, which SDK-M8-07 adds and an app offers on the `bridge_alarm` reason `forwarding_revoked`; setup has no other app-facing API.

**SDK-M8-10 (the push sender), SDK-M8-12 (FS-36, FS-120), SDK-M8-14 (the quick burner), SDK-M9-01 (CheckSend).** Unchanged. A wake reaches the app's sidecar role only; the VPN component takes `team` hints on D or by F's long-poll and needs no wake.

**SDK-M10-01, -03, -04, -05, -06 (search and drops).** Unchanged. SDK-M10-02 changes by one line, as listed. -06's T4 legs run beside SDK-M8-15's forwarding cells and must not count the compile's transient heap against search's working set: sample each alone.

### 4.8 Proposed DESIGN.md text

For the design-records track, section by section; each replaces the sentence or row named.

**§17.8, `Forwarding roles`.** Replace "between compiles its posture applies the log's `SidecarRevoke`, `MemberRevoke`, `Suspend`, `Unsuspend`, `GrantRevoke` and `BridgeWithdraw` entries" with "between compiles its posture applies as denials the log's `SidecarRevoke`, `MemberRevoke`, `Suspend`, `GrantRevoke`, `BridgeWithdraw` and `DelegationRevoke` entries and a newer forwarding Delegation's supersession, each on its signer's identity key in the rows it holds, and lifts nothing: an `Unsuspend` and every opening take effect at the next compile; a statement that could narrow reach and that it cannot check waits for the next compile, the last compiled state staying in force: the component never goes pending for it, and raises `bridge_alarm` with the statement's age once it has waited 10 minutes, again each 10 minutes while it waits, so a revocation the posture cannot check does not apply on a device that cannot compile (QD-621)". Add: "The compile's judge is §7.9's rows-only verifier, as api's: the forwarding role checks a head against the base that names it and does not re-compile rows from it."

**§17.8, `persist` row.** Add "sealed under forwarding's root key; the highest pin committed is also kept in the key store, and a store below it is pending".

**§17.9, `verify` row.** After "by the key of the subject's forwarding Delegation live at this state" add "(a 32-byte signer_id is its delegation_id, verified only under that subject's `BridgeIdentity.forward_public_key`), which the host denies again from the entry that revokes or supersedes it".

**§18.4, the host table's iOS row.** "network extension; 18.10's budget" stands; the budget's numbers change in 18.10.

**§18.6, `deviceBridge`.** `SetState(state *bridge.BridgeState, log *device.PostureLog) error` and `ApplyDeltas(log *device.PostureLog) error`, with the comment "the log run that vouches for the state, from the component's own store".

**§18.6, Setup.** Replace the block's `keys` to `hand off` rows with 4.2.6's steps C0 to C8, and add its `kill` row. Add to `when`: "and when no forwarding Delegation of S is live".

**§18.6, Following.** Replace the `follow` row with: "it fetches the log with F's token and hands each page to its posture, which applies denials at once; when an entry is not a denial it runs a compile off the packet path: a rows-only `ConfigLog` restored from its store judges the entries, DelegationWraps open the generations, the head the base names is read and checked against it, and `AclState` and §17.8's compiler produce S's state, all released afterwards; a compile is admitted by an estimate of about five times its rows' bytes against the host's cap and heap ceiling, and one refused or deferred leaves the last state in force, never pending, and raises `bridge_alarm`". Add to `witness`: "a fork the sidecar role finds forces the forwarding role pending".

**§18.6, posture block.** `stored` gains "the entries waiting for a compile with the time each was first seen, which times the alarm and nothing else, and a fork its sidecar role reported"; `never` gains "a state below the one in force, or a store below the key store's floor".

**§18.10, Forwarding leg.** Replace `kept` and `excluded` with 4.2.3's first block. Replace `make size` with "from M4 the leg adds at most 6 MiB, measured stripped, over the pre-sidecar extension (5,040,248 B measured on 2026-11-10 before the bridge files), and the signed iOS extension's ceiling rises from 50 MiB to 54 MiB (QD-619)". Replace `memory` with "forwarding's Go heap at most 4 MiB steady; a compile is transient and admitted by an estimate of about five times its rows' bytes against 10 MiB and a 30 MiB process ceiling in the Apple extensions, about 4,300 devices' rows, past which the network keeps its last compiled state on that device, applies every revocation it can check and raises `bridge_alarm`, and is pending there only if it never compiled (QD-620, QD-621); bulk state stays on storage and RAM is a working set, so the review phase's path past the cap is a storage-backed compile that reads its rows from the sealed store under the same cap (QD-641)".

**§18.11.** Add rows: "A file allow-list of forwarding files alone | a short list | the root's files are not layered: the closure is 269 of 428 | not available without seam work: a computed list, tags on the rest, and the linker" and "The follower kept resident in the tunnel | no reload a compile | 10.5 MB decoded at 5,000 devices | rejected: transient compiles".

**§18.12.** D-SDK-13 gains "the posture applies denials at once and opens only on a compiled state; a narrowing entry it cannot check never makes it pending: the last compiled state stays in force and `bridge_alarm` is raised from 10 minutes on, repeating, until a compile judges it (QD-621)". D-SDK-20 becomes "The forwarding role is `sidecar/device` with the root files on the `ios_extension` leg's list, a computed closure every other root file is tagged out of, whose list, refused modules and stripped size `make check` and `make size` hold". D-SDK-32 gains "its reader key is a gkm object named by the row's digest; a key set is promoted only when the component's own state shows its Delegation live".

**§18.13, Q-SDK-7.** Decided (QD-619, QD-620): 6 MiB stripped, 54 MiB, 4 MiB steady, the compile's admission rule and its 10 MiB cap.

**§7.9, the proto block and the forwarding row.** Add `ForwardScope` and `DelegationRow` 12 to 16 with 4.2.2's comments. In the row replace "a newer one of S supersedes it at its position" with "a newer one of S supersedes it at its position, recorded as superseded_at, which is no end for §10.5"; add "its row carries its reader key's SHA-256, never the key".

**§10.5, `dwraps` and the holder table; §10.6's object table.** Add the object `gkm/dkey/<delegation_id>` ("a forwarding Delegation's reader key, 1,216 B, If-None-Match by its signer, its SHA-256 the row's reader_key_sha256; rotators and gkm check the digest; deleted 24 h after the Delegation ends or is superseded") and the two routes; in `dwraps`, "its sidecar uploads the key object, then writes the wrap".

**§8.8.** The rows budget note gains "a forwarding Delegation's row is about 200 B".

**§2.8.** gkm-1's `sees` gains "and each forwarding Delegation's reader public key, by delegation_id"; api-7's Delegation line gains "a forwarding Delegation's reader key digest, host client and supersession position".

**§5.9, `Forwarding's keys`.** Add "in two slots, current and next, a set promoted when the component's state shows its Delegation live; and the floor, the highest pin committed".

**§4.7, the legs row; §4.9.** The `ios_extension` rule becomes REPO-M4-01's three rules; `make size`'s row reads stripped.

**§22.5's §17 row, §22.9's Memory row, FS-14, FS-18, FS-38.** The cases 4.6 names; the Memory row's "compiles a 5,000-device team's config" becomes "compiles a 3,000-device team's config within its cap and refuses a 5,000-device one with the alarm".

**§17.17.** The row "Links, or forwarding's compile, do not fit the iOS tunnel" gains the measured bound; add "A revocation the posture cannot check does not apply on a device that cannot compile | Low | High | accepted by the owner (QD-621): forwarding never drops for it; `bridge_alarm` from 10 minutes on, repeating; denials it can check apply at once; the review phase's storage-backed compile removes the memory cap as a cause".

**RESOLUTIONS.** sdk-m4-01-state-proof: superseded by decision 197; the component fetches the log itself and `SetState(state, log)` stands. sdk-m4-02-make-size-over: option 2, with the limit Q-SDK-7 sets. plan-BRIDGE-keyless-window-parent and plan-SDK-small-readings #11: no longer apply on app hosts.

### 4.9 Owner questions

Each is filed under `.stack/questions/`, and the section was built on the recommendation in every case. The owner answered all four on 2026-11-10: three on the recommendation, and the compile deadline on option 2, which 4.2.5 and 4.3 now carry. Each answer follows its question, with its ledger id.

**details-4-ios-forwarding-budget** (Q-SDK-7's executable half, with measurements; it also settles sdk-m4-02-make-size-over). Options: (1) the leg adds at most 6 MiB, measured stripped, and the signed extension's ceiling rises from 50 to 54 MiB; (2) hold §18.10's proposed 4 MiB; (3) hold 1 MiB with a second follower, policy evaluator and compiler in `sidecar/device`. Costs: (1) a ceiling the owner has raised by review before, and about 1 MiB of static memory; measured 5,040,248 B today, about 5.4 MB with the bridge files; (2) not reachable with the shared judge, whose measured floor is 4.4 MB before evs head reads, gkm and the compiler, so it means (3) for part of the rules; (3) two implementations of security-critical rules to keep equal. Recommendation: (1). **Answered: QD-619, option 1**: the leg adds at most 6 MiB stripped and the signed extension's ceiling is 54 MiB; REPO-M4-01's size row and `check_apple_size.sh`'s ceiling are decided, no longer proposed.

**details-4-ios-compile-memory** (Q-SDK-7's memory half). A compile needs about five times the rows' bytes. Options: (1) cap a compile at 10 MiB under a 30 MiB process ceiling in the Apple extensions: networks to about 4,300 devices compile there, larger ones stay pending on iPhones and Macs' extensions with an alarm, and under provider load a compile waits; (2) cap 12 MiB with the ceiling at the 32 MiB soft limit, which admits a 5,000-device team only while the tunnel is otherwise idle and leaves the collector no room; (3) for networks over the cap, the app's sidecar role compiles and hands the state with its log run over the device RPC, as the keyless role did, which waits on the app; (4) a compact, per-host state in the shared verifier (core lane), which removes the bound and is a rework of `ConfigState`. Recommendation: (1) now and (4) as review-phase work if large teams on iOS matter; not (3), which decision 197 ruled out. **Answered: QD-620, option 1**: a 10 MiB cap under a 30 MiB ceiling. Two later answers change what the option's words say. Under QD-621 a network over the cap is not pending: it keeps its last compiled state and alarms. Under QD-641, the owner's direction that bulk state live on storage, the review-phase path past the cap is not option (4)'s compact per-host state but a storage-backed compile under the same cap (4.2.4).

**details-4-forwarding-reader-key-in-rows.** Options: (1) the row carries the reader key's SHA-256 and the key is a gkm object; (2) keep the 1,216 B key in the row; (3) X25519-only reader keys for forwarding, 32 B. Costs: (1) one object family, two routes, a digest check at rotators, a §2.8 line for a value rows already showed; (2) §8.8's 4 MiB cap at about 2,600 app devices, and three times the compile memory; (3) config generations wrapped to a forwarding key lose post-quantum protection against a recorded wrap. Recommendation: (1). **Answered: QD-622, option 1**: the row carries the key's SHA-256 and the key is a gkm object; TEAM-M2-20, TEAM-M8-01 and KEYS-M8-01 landed it.

**details-4-compile-deadline.** What a VPN component does when a statement that could narrow reach has waited for a compile that has not run. Options: (1) pending after 10 minutes; (2) keep the last state indefinitely and alarm; (3) pending after 60 seconds. Costs: (1) forwarding stops on a device under sustained memory pressure in a busy team, and resumes at the next compile; (2) a revocation the posture cannot check (its signer admitted since the base, or made by proposal, tick or cascade) may never apply on a device that cannot compile; (3) ordinary compile deferrals under provider load would drop forwarding. Recommendation: (1). **Answered: QD-621, option 2, not the recommendation**: keep the last state indefinitely and alarm. The component never goes pending for a statement it cannot check; it applies at once every revocation it can check, raises `bridge_alarm` with the statement's age at `NarrowingOverdueTimeout` and again each period while it waits, and the next compile judges every waiting statement. The cost in (2) is accepted. 4.2.5, 4.3, 4.5, 4.6 and `Fwd.tla` are amended to it.

Q-BRIDGE-8 (design-od197-app-address-at-setup) stays open and unchanged: this section builds on its option 1, on demand.

None blocked the held tasks. With the answers, SDK-M8-17 builds 4.2.5 as amended, and REPO-M4-01's limit is decided (a note for its entry is in `.stack/plan/proposals/owner-answers-tasks.md`).

## 5. Authorization-log verdicts across folds (§7.9)

Status: complete (2026-11-09)

Amended 2026-11-10 for the owner's answers: QD-628 (in `AuthLog.tla` a recovery-signed proposal stays pending at any cosign until its tick, and the recovery cosign is in every run's alphabet: 5.3's WindowHolds, model and runs). 5.9 records every answer, QD-627 to QD-629. Nothing of 5.2 changes.

Tasks held until complete: CORE-M3-02, CORE-M3-03, TEAM-M10-01, TEAM-M2-04, TEAM-M2-05, TEAM-M2-06, TEAM-M2-07, TEAM-M2-09, TEAM-M2-10, TEAM-M2-17, TEAM-M2-18, TEAM-M2-19, TEAM-M3-02.

Model: `sidecar/sidecartest/model/details/AuthLog.tla`, its configurations and `run.sh` beside it. Questions filed: `.stack/questions/details-5-settings-in-rows.md`, `.stack/questions/details-5-base-records-in-folds.md`.

### 5.1 The problem

§7.9 defines one state per log position, S(n): the newest base b at or below n gives rows that compile its config head, which holds every statement and tick up to b's `folded_through` (m below); the statements and ticks among m+1..b-1 (the *tail*) re-apply on those rows; then the entries b+1..n apply in order. A statement's *verdict* is judged once, at its own position, against S(n-1), and the BASE row has the tail "keeping the verdict it got at its own position". Three kinds of verifier read the same log: a long-running reader (a device present since the bootstrap base, which judged every entry itself), a new device (one that starts at the newest base, holding rows, the entries from api's retention point r = min(the previous base, m+1), and no state before b), and a rows-only verifier (api, evs, gkm and the other gates, which hold no config key and never open a head). D-TEAM-19 and D-TEAM-20 require that they all hold one S(n) and one verdict per entry ("equal pins give equal verdicts"), because the gates decide reads and writes from S(n) and devices decide keys, commits and alarms from it.

Four places break that today, and the three the brief names are the first three.

**Tail verdicts at a new device (question team-m2-02-new-device-tail-verdicts).** A long-running reader judged a tail statement at position k, m < k < b, against S(k-1), whose head-derived parts (policy, tag owners, ServiceSettings) came from the base current at k-1, and whose retention point was that state's. A new device holds only b's rows, which compile b's head, so it judges the same statement under b's head and under its own first held position. Two concrete runs, with positions:

1. Entry 1: admin device A (member M1, who owns tag `t` in the policy) admits agent D with tag `t`; accepted. Entry 2: a base with `folded_through` 0 whose config head moves `t`'s ownership to M3. A long-running reader keeps entry 1 accepted and D admitted. A new device starting at base 2 judges entry 1 on base 2's rows, where M1 owns no tag: refused, D never admitted. The same shape arises from a `self_admit` edit at the base and a member's self-admission in the tail.
2. Entry 1: a statement signed at pin 0, when the log held no base, so its `at` is 0; accepted at retention point 0. Entry 2: base b1 with `folded_through` 0 (retention point 1). Entry 3: base b2 with the same `folded_through` (retention point min(b1, 1) = 1). A new device at b2 holds entries from 1 on and A_k from 0 on, so it can check entry 1's `at` is on its chain, but the replay row says `at` must not be before "the retention point of the state it lands on", which the new device takes as its own first held position, 1: refused. The long-running reader accepted it. The landed `configTailRetentionPoint` makes exactly this choice.

In both runs the two readers then disagree on every later state, with no FORK: each chains the same A_n.

**Open proposals across a base (question team-m2-02-open-proposals-across-bases).** An AuthorityProposal stays open until its k-th counted cosign or, with a recovery signature, until an ApiTick 72 h after its newest such signature. A writer folds every 1,024 entries or 24 h, so every recovery window and any proposal whose cosigners take a day is folded under a base before it completes. ProjectionRows has no field for an open proposal. §7.9 as written leaves a long-running reader carrying the proposal in its own state and a new device starting without it: entry 1 proposes (k = 2), entry 2 is a base folding through 1, entry 3 cosigns; the long-running reader completes the admission, the new device refuses the cosign as naming no open proposal. The landed `stateFromBase` closes every proposal at a base on every reader instead, which keeps them equal and breaks every recovery window and every slow k-of-n proposal (`TestAProposalABaseFoldsCloses`).

**Self-admission at rows-only verifiers (question team-m2-02-self-admit-at-rows-only-readers).** The scoped row admits a member's untagged device on its consented device's signature "only while self_admit is on", and `self_admit` rides config heads only (plan-TEAM-config-head-format #2). api verifies every statement against S(tip) before it appends one, and api never opens a head (plan-TEAM-api-config-head-reach), so api cannot judge the one statement every personal network's second device needs. The landed code fails closed (`ErrConfigSettingsUnknown`), which means api answers 403 to every self-admission while every device would accept it: the split D-TEAM-19 exists to prevent, at the most common admission there is.

**The replay ring at a new device, found while modelling.** A statement is refused when its id is among the last 4,096 entries' applied ids. A new device holds no verdict for entries the base folded, and the landed `restore` takes every folded statement as applied for the ring. A vetoed recovery proposal, replayed verbatim after a fold, is refused by a long-running reader and accepted by a new device whose rows hold no record of it (the closed proposal left the state, and the id left the ring), so the vetoed window runs again, the hole protos-bridge-statement-id-wrapper's table names. The converse also diverges: a refused statement resubmitted verbatim once its reason has passed.

Two smaller gaps sit beside these. `SidecarRow` keeps only the newest AdmissionConfirm and OwnerConfirm, while the cascade's "a confirmation of a device then unparked and consented on other signatures adding none" and "whose consent rests only on such a sidecar's OwnerConfirm" need every confirmation with its signer and position, so a rows-only verifier computes a different P from a device that kept the entries (ACL-M2-03's note). And a new device's head check has no state to compile against: `CheckConfigBase` refuses a check with no `Previous`, so the anchor a new full device runs on its first base is unbuilt.

The requirement: every verifier reaches the same verdict on every statement and the same S(n) at every position it stands at, whatever base it started from and whatever it can open; a verifier that cannot reach that state forks visibly rather than diverging silently; and the log stays safe through the compromise cascade, recovery, folding and site-loss resumption.

### 5.2 The design

#### 5.2.1 The principle

**A verdict is judged once, at the entry's position, by the verifiers present there, and every later verifier takes it from the next base.** A base carries the verdict of every entry in its tail; its rows carry a complete state at `folded_through` for a verifier that holds nothing else, open proposals, the replay ring, the id-level settings and every confirmation included; no verifier ever re-judges a tail, and every verifier re-applies a tail by its verdicts. A long-running reader checks the base's verdicts against its own and forks on a difference, so a writer cannot split the readers: it can only fork itself off. This keeps §7.9's BASE row ("each keeping the verdict it got at its own position, so a later authority change never undoes an earlier revocation, while effects that depend on rows follow the new rows") and makes it computable from a base alone.

Every change below is additive to the wire, which owner decision 194 leaves unfrozen until M2's Gn-in, and is a format change, so each needs its §2.8 line (I-18) where a server reads it; 5.8 gives the lines.

#### 5.2.2 What a base and its rows carry

```proto
// sidecar/protocol/bridge/auth.proto, additions; numbers follow the order written
message ProjectionHeader {
  // fields 1-9 as today
  bytes  tail_verdicts = 10;         // 2 bits per entry among folded_through+1..version-1, in position order:
                                     //   entry folded_through+1+j is bits 2j and 2j+1 of byte j/4, bit 0 the
                                     //   byte's least significant; 0 refused or a BASE, 1 took effect, 2 took
                                     //   effect and completed a proposal (an AuthorityProposal at k = 1 or the
                                     //   k-th AuthorityCosign only), 3 never; exactly ceil(2*(version-1-
                                     //   folded_through)/8) bytes, padding bits 0; empty when nothing is unfolded
}
message ProjectionRows {
  // fields 1-5 as today; 6 reserved for TeamScopeRow at M6 (protos-bridge-row-fields #3)
  repeated ProposalRow proposals = 7;    // every proposal open at folded_through, by proposal_id
  ProjectionSettings settings = 8;       // the ServiceSettings values a verifier judges by
  repeated RingRow ring = 9;             // the statements that took effect among the 4,096 entries through
                                         //   folded_through, in position order (the replay row)
}
message ProposalRow {
  bytes  proposal_id = 1;                // 32 B
  uint32 statement_type = 2;             // the proposed statement's SignedType
  bytes  statement = 3;                  // AuthorityProposal.statement, verbatim
  uint64 proposed_at = 4;                // o: the AuthorityProposal's entry
  int64  not_after_ms = 5;               // the proposal's own header's
  repeated ProposalSigner signers = 6;   // the proposer, then each counted cosign, in log order
  uint64 window_entry = 7;               // p: the entry of the newest recovery-key signature; 0 with none
  int64  window_time_ms = 8;             // T_p: that entry's time_ms
  uint32 kind = 9;                       // ProposalKind, fixed at the proposal's entry
}
message ProposalSigner {
  bytes  signer = 1;                     // as rows name one: a sidecar_id or a recovery key's hash
  uint64 at = 2;                         // the entry that carried its proposal or cosign
}
enum ProposalKind {
  PROPOSAL_KIND_UNSPECIFIED = 0;
  PROPOSAL_KIND_AUTHORITY = 1;           // k of n (7.9's several row)
  PROPOSAL_KIND_RECOVERY_SCOPED = 2;     // a scoped recovery admission filed with self_admit off: completes on one
                                         //   cosign by an admission signer (7.9's self_admit row)
  PROPOSAL_KIND_RESTORED = 3;            // a restored binding's scoped admission: activates at the window with no
                                         //   counted cosign (owner decision 149)
}
message ProjectionSettings {
  uint32 self_admit = 1;                 // SelfAdmitMode's value: 0 unset (on), 1 on, 2 off (owner decision 112)
  bytes  scim_signer = 2;                // ServiceSettings.scim_signer (7.6), empty for none
}
message RingRow {
  bytes  statement_id = 1;               // the first 16 B of the statement's id (RetainedStatementId)
  uint64 n = 2;                          // the entry that carried it
}
message SidecarRow {
  // fields 1-20 as today; 5-8 stay the newest AdmissionConfirm and OwnerConfirm
  repeated ConfirmationRow confirmations = 21;   // every one that took effect, in position order
}
message ConfirmationRow {
  uint32 kind = 1;                       // 1 AdmissionConfirm, 2 OwnerConfirm
  bytes  signer = 2;                     // the confirm_signer or owner_confirm_signer it set
  uint64 at = 3;                         // its entry
  bool   lifted_park = 4;                // the device was parked when it landed (7.9's lift row)
}
```

```proto
// sidecar/protocol/config.proto: ConfigRecord.kind gains 1 (BASE), its body the Signed ProjectionHeader, so a fold
// holds every entry in (after, folded_through] and a reader recomputes A_k from the genesis through the head alone
```

Encoding and order, which every compiler on every leg must give alike, since `rows_sha256` hashes them: `proposals` sorted by `proposal_id` bytes; `signers` in log order; `ring` in `n` order; `confirmations` in `at` order; `settings` always present, its zero value meaning the defaults; `tail_verdicts` as the comment says, little-endian within a byte, two bits per entry, so a tail of 1,024 entries is 256 B and the cap below bounds it at 1 KiB.

**Compile.** `compile(head, L)` takes the head and L, the *log-derived rows at folded_through*: members, sidecars (confirmations included), Delegations, registered keys, the open proposals, the ring and AclRows' statement-derived rows, exactly `ConfigCompileRows` plus proposals and ring. It writes `settings` from the head's `ServiceSettings` (absent: the zero value), `proposals` from L's open ones, `ring` from L's, and the acl part as ACL's `CompileAcl` does. A proposal is *open at ft* when it took effect, has not completed, been vetoed or voided, and its `not_after_ms` is not below the entry time at ft, T_ft (never a clock; with BASE records in folds every position has a time). A ring entry is kept when its `n` is above ft - 4,096.

L is defined by one recurrence so that the writer and every reader compute it from what they retain. With b' the previous base, ft' its fold and R_b'(k) the state rebuilt from b''s rows by re-applying the entries ft'+1..k by their verdicts (BASEs skipped): L(ft) = LogPart(R_b'(ft)). Since the entries b'+1.. apply by the same re-application rule, R_b'(k) = S(k) for k >= b', so a reader uses `StateAt(ft)` when ft >= b' and b''s retained rows when ft = ft'. Those are the only two cases, by the next rule.

#### 5.2.3 The rules

**folded_through.** A base's `folded_through` is either the previous base's or at least the previous base's position: ft = ft' or ft >= b'. api answers 403 to any other value; a reader forks on it. (A writer never folds part of a previous base's tail: it folds through the tip, or keeps the fold where it was for a policy-only base.)

**Tail cap.** version - 1 - folded_through <= 4,096 (`configTailMax`, a protocol constant beside the 4,096 of the replay row). api answers 403 above it; a reader forks on it. A writer that finds the tail longer, after an outage, folds through the tip first; §7.9's fold row (1,024 entries or 24 h) stays the soft trigger. This bounds every verifier's re-application, the header's bitmap and {acl_}e's needs.

**The base's verdicts.** The writer fills `tail_verdicts` from the verdicts it holds for ft+1..n-1: its own where it judged, the previous base's bits where it took them. Every verifier that holds a verdict for a tail position compares: a differing bit, a 2 on an entry that is no AuthorityProposal or AuthorityCosign, a 3, or a wrong length is a FORK naming the position (the writer lied, or diverged). A verifier that holds none takes the bits.

**Re-application** (`Reapply(state, entry, verdict)`): for each tail entry with verdict 1 or 2, parse the body and apply its effect on the state being built; never verify a signature, a header, a signer's standing or a type rule. An AuthorityProposal with verdict 2 applies the proposed statement with signers [proposer]; with 1 it opens a ProposalRow. An AuthorityCosign with 2 applies the proposed statement with the row's signers plus the cosigner and closes the row; with 1 it appends the cosigner. A TICK applies its reaps and each activation, closing the row and applying its statement with the row's signers. Every other statement applies its effect as its type's `apply` says, an acl effect dropped where the new rows no longer allow it (ACL's `ReapplyStatement`, plan-ACL-folded-grant-state #2). An effect reads only the statement's body and the log-derived state being built, never what the check found on a head at the entry's own position: the row signer, `lifted_park`, `live_since`, `key_dropped_at` and `holders_shrunk_at` are recomputed on the rebuilt state, which every verifier holds alike. The verdict and the completion are never recomputed: they come from the entry's own judgment, or the bits.

**Open proposals.** Rows carry every open proposal; the tail re-opens, advances, completes, vetoes or voids them as its verdicts say; after the base, cosigns, vetoes, rebinds, AdminSet changes, removals and ticks find them in S(n) at every verifier alike. The window's activation reads `window_time_ms` from the row, so T_p is known where the entry p is below the retention point. `kind` is fixed when the proposal takes effect, from the signer's kind, whether the member is in the AdminSet, whether the binding is one a void restored, and `self_admit` then, so the activation rule needs none of those at the tick. Voiding, vetoing and completion delete nothing: the row closes with the position and reason, `OpenProposalIds` filters, and compile drops closed and expired rows.

**Self-admission at rows-only verifiers.** `ProjectionSettings.self_admit` is what every verifier judges the scoped row by; `ConfigState.Settings()` loses `known`, and the head's other values (`team_mail`, `stale_leaf_days`, `witness_bound_hours`, `directory`) stay head-only, read by devices alone. `scim_signer` rides beside it, since the MemberRevoke an admin's indexer signs under 7.6 is judged at api too (M6). A full reader checks `settings` against the head at compile; a rows-only verifier takes it.

**The ring.** `ProjectionRows.ring` holds the ids that took effect among the 4,096 entries through ft; a verifier's ring at n is that, plus the tail's entries with verdict 1 or 2, plus what it judged since, trimmed to the 4,096 before n. The replay row's "before the retention point" clause is what makes this exact without the ring reaching further: a statement applied at m0 carries at <= m0 - 1, so a copy landing after the retention point has passed m0 fails the `at` rule before the ring is asked. The ring is therefore the same set at every verifier for every position it is asked at.

**Confirmations.** `SidecarRow.confirmations` keeps every AdmissionConfirm and OwnerConfirm that took effect, with its signer, entry and whether it lifted a park, for the sidecar's life; fields 5-8 stay the newest of each. The cascade reads the history: "whose park such a sidecar's AdmissionConfirm lifted" is a confirmation with `lifted_park` by a signer then in P from since_n on; "a confirmation of a device then unparked and consented on other signatures adding none" is one with `lifted_park` false whose device's consent (§8.5) also rests on a signature outside P; "whose consent rests only on such a sidecar's OwnerConfirm" is a device every consent basis of which, admission signers, invite, genesis and confirmations alike, lies in P or in a key of a binding P voids. P is a pure function of rows, so api, evs, gkm, a new device and a long-running reader build it alike.

**BASE records in folds.** A fold's `ConfigRecord`s include the BASE entries in (after, ft], kind 1, body the Signed ProjectionHeader, so the head holds every entry's body and a reader holding the genesis recomputes A_1..A_ft from the head alone (A_n = SHA-256(... u64be(n) || A_{n-1} || u32be(kind) || i64be(time_ms) || SHA-256(body))). Compile ignores them; the head check compares them like any record. This closes the far-behind reader's gap (5.5) and gives the new device's anchor a chain it can verify to its first retained entry.

**Owner decision 197's forwarding key.** No proposal file exists yet (`.stack/plan/proposals/od-197-forwarding.md` is unwritten). Whatever statements the design-od197 track gives the forwarding key, the rules above hold for them unchanged if they are ordinary log statements: a `StatementHeader`, a rule in the rule table judged once at the entry's position, a verdict carried in `tail_verdicts`, and a fold into a row that keeps the signer and the carrying position. The natural fit is `KeyRegister` and `KeyRevoke` with a new `KEY_PURPOSE_FORWARDING = 3`, the key's `member_id` its device's member and its `signer` the device's sidecar or its member's consented device, folded to `KeyRow` as presence keys are; then the cascade voids a forwarding key a sidecar in P registered exactly as it voids a presence key, a rows-only verifier (the VPN component itself may be one, since it needs no config key to verify the log) judges its registration by `KeyRow`, and nothing else in this section changes. If the track makes the key a Delegation instead, `DelegationRow` already carries what this section needs.

#### 5.2.4 Algorithms

Notation: `S` a `ConfigState`; `S.rows` its log-derived rows; `V[k]` the verdict held for position k (0, 1, 2); `held` the first position a verifier holds an entry at; `r(b)` the retention point a base sets, min(b', ft+1), or ft+1 for the first base after bootstrap.

```text
Judge(S, entry e at n)                          -- unchanged: §7.9's statement row at S(n-1)
  parse Signed; verify under the signer S names; replay rules at r(S) (at on S's chain, within 4,096,
  not before r(S), unexpired, id not in Ring(S, n)); read_only; presence; the type's rule
  -> 0 refused | 1 effect | 2 effect and completes a proposal

Reapply(S, e at k, v)                            -- never judges
  if v = 0 or e is a BASE: return S
  parse body (no signature check)
  case AuthorityProposal:  if v = 2: apply(proposed, signers=[proposer]) else open ProposalRow(kind fixed now)
  case AuthorityCosign:    row := S.proposals[pid]; if v = 2: apply(row.statement, row.signers + cosigner); close row
                           else row.signers += cosigner
  case TICK:               revoke each reaped id; for each activated pid: close row; apply(row.statement, row.signers)
  otherwise:               rule.apply(S, e) on the rebuilt state (ACL: ReapplyStatement)
  S.ring += (id16(e), k); return S

ApplyBase(V, base e at n)                        -- a verifier already standing at S(n-1)
  h := parse Signed ProjectionHeader
  require h.version = n, h.prev_chain = S.A, signer is a config writer at S, signature verifies  else FORK
  require h.config_version >= prev.config_version, h.folded_through >= prev.folded_through        else FORK
  require h.folded_through = prev.folded_through or h.folded_through >= prev.base                 else FORK
  require n - 1 - h.folded_through <= 4096                                                        else FORK
  rows := fetch(projrows/h.rows_sha256); require sha256(rows) = h.rows_sha256, len = h.rows_byte_count <= 4 MiB
  bits := decode(h.tail_verdicts, n - 1 - h.folded_through)            -- length and padding exact, no 3 else FORK
  for k in ft+1..n-1:
      if e_k is a BASE: require bits[k] = 0                                                       else FORK
      else if V holds V[k]: require bits[k] = V[k]                                                else FORK
      require bits[k] = 2 only on an AuthorityProposal or AuthorityCosign                         else FORK
  if V is a full reader:
      L := LogPart(ft = prev.folded_through ? prev.rows : StateAt(ft))
      require CheckHead(head(h.config_head_sha256), prev, L, rows): genesis, descent, records (BASEs included),
              settings signer, compile(head, L) = rows                                            else FORK
  S' := Load(rows); S'.base := h; S'.previousBase := prev.base; S'.retentionPoint := r
  for k in ft+1..n-1: S' := Reapply(S', e_k, bits[k])
  V[k] := bits[k] for every tail k V did not judge
  retain(S', rows); publish S'

StartAtBase(V, b)                                -- a new device, a cold gate, or a reader that fell behind
  fetch entry 0 (the Signed Genesis; A_0 must equal the invite's or the bundle's), entries r(b)..tip, rows(b)
  chain A_k forward from entry r(b)'s prev_chain; every link must hold                           else FORK
  h := parse base b; require sha256(rows) = h.rows_sha256 and h's signer is a config writer in rows(b)
          whose identity key in rows(b) verifies h's signature; tail cap; ft rule against the previous base if held
  if V is a full reader (anchor):
      head := open(h.config_head_sha256); require head.genesis = A_0; head on the config repo's chain from
              genesis (evs; config_pushes at api); head's fold records equal every held entry in [r(b), ft];
              recompute A_1..A_{r(b)-1} from the genesis through the head's records, BASEs included, and require
              the result to equal entry r(b)'s prev_chain                                         else head_alarm
      settings in rows equal the head's ServiceSettings
  S := Load(rows(b)); S.base := h; bits := decode(h.tail_verdicts)
  for k in ft+1..b-1: S := Reapply(S, e_k, bits[k]); V[k] := bits[k]
  ring := rows.ring + {applied tail ids}; retentionPoint := r(b); held := r(b)
  for k in b+1..tip: Apply(e_k) as a long-running reader (Judge, then effect)

WriterPublishBase(W, head)                       -- a config writer at S(tip), TEAM-M2-09
  ft := tip if folding, else prev.folded_through; require tip - ft <= 4096 (else fold through tip first)
  L := LogPart(ft = prev.folded_through ? prev.rows : StateAt(ft))
  rows := compile(head, L)                       -- settings, proposals open at ft, ring through ft, acl
  bits[k] := V[k] for k in ft+1..tip (0 at a BASE); h := ProjectionHeader{version tip+1, prev_chain A_tip,
      folded_through ft, config_version, config_head_sha256, rows_sha256, rows_byte_count, threshold, tail_verdicts}
  POST /network/config/projection {Signed h, rows, config_pushes}; on 409 re-sign at the new tip (re-compile only
      if the head or the fold moved), extending bits with the new tail's verdicts

ApiAcceptBase(e)                                 -- api, a rows-only verifier at S(tip), TEAM-M2-13
  as ApplyBase without the head check, every FORK a 403 {tip, A_tip} with the reason; then PUT projrows, the entry
```

The equal-verdict argument, in short: a verifier judges an entry only at a state every verifier present holds (S(n-1), by induction from the previous base), so present verifiers agree; a verifier not present takes the bits, which the present verifiers checked, so it agrees with them or they forked; rows at ft equal LogPart(S(ft)) by the full readers' compile check, with every rows-only input a verifier judges by (settings, proposals, ring, confirmations) inside them; and the ring needs no position below the retention point, by the `at` rule. 5.3 states the invariants and checks them.

### 5.3 Invariants and why they hold

```text
Agreement        every verifier that stands on the log, not forked, holds the same state at each position n at or
                 past the base it started at, and the same verdict for each entry both hold a verdict for
                 why: a verdict is judged once, at S(n-1), which present verifiers share by induction; absent ones
                 take the base's bits, which present ones compared; rows carry every rows-only input (5.2.3)
RevocationsStand a revocation that took effect is in effect at every later state
                 why: no verifier re-judges a tail; a base re-applies by verdict, and a revocation's effect depends
                 on no head-derived row
CascadeClosed    a compromise revocation of x from since_n parks every sidecar the design's closure holds, each
                 record counting from its carrying entry, however its signer dated its at
                 why: P is a function of rows (admission signers and positions, every confirmation, bindings,
                 Delegations), the carrying position is api's, and the statement's at is the signer's claim
DelegationEnds   no admission a Delegation's key signs takes effect after the Delegation ended
                 why: DelegationRow.ended_at is in rows and the tail advances it by verdict
ProposalsNeedK   a proposal completes only with k distinct counted members at the completing entry's state
                 why: ProposalRow keeps each signer; completion is judged once, at that entry, and carried as 2
WindowHolds      a recovery proposal takes effect only at a tick at or after T_p + 72 h, T_p the entry of its
                 newest recovery signature, with no valid veto between its entry and the tick; no cosign
                 completes one, a device's k-th included
                 why: window_entry and window_time_ms are in the row; a veto closes the row at its position;
                 a cosign of a recovery row returns 1 and leaves the row open (§7.9's pending row)
TailBounded      no base leaves more than 4,096 entries unfolded
LiesAreForks     a base whose bits disagree with a present verifier's verdict forks that verifier
ProposalsSurviveFolds
                 a counted member's cosign of a proposal the log itself shows open takes effect, however many bases
                 lie between the proposal and the cosign
```

**The model.** `sidecartest/model/details/AuthLog.tla` keeps the log as its one shared object and three verifiers as variables derived from it: `L`, the long-running full reader and writer; `N[b]`, a new full device started at each base b; and `G`, the rows-only gate cold-started at the newest base, which is what api sequences by. It models admissions with signers, carrying position, the signer's `at`, confirmations, parks and revocations; one Delegation with `max_admits`; recovery bindings, recovery-signed proposals, their device cosigns and recovery cosigns, the 72 h window, vetoes and ticks; AuthorityProposals and cosigns at threshold K; the compromise cascade with consent (§8.5), voids of bindings and Delegations and the parks a Delegation's end makes; the replay ring and the `at` rule with the retention point; and bases with `folded_through`, head-derived rows (`self_admit`, a tag's owner), tail verdict bits and, under `LyingWriter`, a lie; under `Adversary` api sequences refused statements too. It leaves out presence countersignatures, read_only, `not_after` expiries, EvsShares, key registrations, leaf ranks, the head's own chain and api's reap ticks. The clock is the position. `Twin` selects a rule to break: `JudgeTail`, `NoProposalRows` and `NoSettingsRows` are §7.9 as written on 2026-11-09 and `CloseAtBase` the landed code; `ReJudgeTail` (the question's option 2), `NoRingRows`, `CascadeFromAt`, `NoBitsCheck` and `NoTailCap` each break one rule of this design. `Story` fixes a twin's entries so TLC reaches its violation directly; the design runs with none. `run.sh <track>` runs every configuration through `.stack/tools/tlc` and prints a verdict line per run.

Runs, TLC at the owner's jar (master d8fb231), bounded so each finishes; breadth-first over every reachable state at the bounds, but for the deepest design run, which samples. The design rows are of 2026-11-10, on the model with QD-628's change, on a machine carrying four build lanes:

```text
configuration            Twin           K  bounds (Window 4, TailMax 4, RecoveryWindow 2, Life 5, MaxAdmits 2)
                                           result                                   distinct states  depth  time
AuthLog                  none           2  MaxN 4, MaxBases 2, no story, no adversary
                                           pass, every invariant                      1,725,251      5      3 min 12 s
AuthLog-K1               none           1  the same at k = 1
                                           pass, every invariant                      4,061,823      5      18 min 48 s
AuthLog-Adversary        none           2  MaxN 4, MaxBases 2, LyingWriter: a writer may publish a base with a false
                                           verdict (every honest base has a lying twin beside it)
                                           pass, every invariant                      2,494,483      5      7 min 14 s
AuthLog-Narrow           none           2  MaxN 5, MaxBases 2, Narrow: one at and one since_n a statement; by random
                                           simulation, 200,000 traces a worker of up to 7 steps from seed 1, since its
                                           complete graph passes 20 million states
                                           pass, every invariant on those traces   436,846,913 generated  6  1 h 44 min
Twin-JudgeTail-Head      JudgeTail      2  StoryTailHead, MaxN 2      Agreement violated, 3-state trace    3    3
Twin-JudgeTail-At        JudgeTail      2  StoryTailAt, MaxN 3        Agreement violated, 3-state trace    3    3
Twin-NoProposalRows      NoProposalRows 2  StoryProposals, MaxN 3     Agreement violated, 3-state trace    3    3
Twin-NoSettingsRows      NoSettingsRows 2  StorySettings, MaxN 3      Agreement violated, 4-state trace   11    4
Twin-NoRingRows          NoRingRows     2  StoryRing, MaxN 6          Agreement violated, 7-state trace   75    7
Twin-ReJudgeTail         ReJudgeTail    2  StoryReJudge, MaxN 3       RevocationsStand violated, 4 states  4    4
Twin-CascadeFromAt       CascadeFromAt  1  StoryCascadeAt, MaxN 2     CascadeClosed violated, 3 states     3    3
Twin-NoBitsCheck         NoBitsCheck    2  StoryLie, MaxN 2, LyingWriter Agreement violated, 3 states       3    3
Twin-NoBitsCheck-Forks   NoBitsCheck    2  the same                   LiesAreForks violated, 3 states      3    3
Twin-CloseAtBase         CloseAtBase    2  StoryClose, MaxN 3, Adversary ProposalsSurviveFolds violated   12    4
Twin-NoTailCap           NoTailCap      2  StoryTailCap, MaxN 3, TailMax 1 TailBounded violated, 4 states  6    4
```

What QD-628 changed in these runs. A recovery-signed proposal no longer completes at a device's cosign, and the recovery cosign is an entry any design run may take. Each breadth-first count rose a little (by 8, 12 and 8 states). A recovery cosign can only be a run's fourth entry at these bounds, since it needs two bindings and a recovery proposal before it, so the logs it adds are few. The narrowed run, at the size `run.sh` fixes for it (200,000 traces a worker on 14 workers), generated 628 states more than it did on the model as it was; a tenth of it, 20,000 traces a worker, ran first and passed with 43,675,285 states generated in 16 min 8 s. The fifteen twins, the eleven below and the four the TEAM tasks added (`NewestConfirmOnly`, `DelegationEndIgnored`, `WindowFromProposalEntry`, `VoidKeepsProposal`), were run again and each ends on its invariant with the trace it had; the last two no longer add the recovery cosign to their own runs, since every run has it.

Each twin run took under 5 s; a twin's distinct-state count is what TLC had explored when its workers met the violation, so it varies a little between runs (NoRingRows 59 to 75, CloseAtBase 12 to 14) while the trace does not. A depth counts TLC's initial state, so a 3-state trace is two entries. The three breadth-first design runs explore every log the candidate alphabet allows at their depth (about 37 enabled entries a position at MaxN 4); a run one entry deeper multiplies the states by that, so the narrowed depth-5 run, whose complete graph passed 20 million states without finishing in two hours, runs instead by TLC's random simulation, which proves only that the behaviors it drew kept every invariant. Its seed and trace count are fixed in `run.sh`, so the run repeats.

The three divergences appear in the model of §7.9 as written and are gone in the design: `Twin-JudgeTail-Head` and `Twin-JudgeTail-At` violate Agreement at the base (a new device's tail verdict differs from the long-running reader's on a tag owner moved by the head, and on an `at` below the new device's first held position); `Twin-NoProposalRows` at the cosign after the fold; `Twin-NoSettingsRows` at the self-admission the gate refuses; `Twin-NoRingRows` at the vetoed recovery proposal's replay. The design's runs hold every invariant at the same and larger bounds, with Agreement comparing every new device and the gate against the long-running reader at every state.

### 5.4 Cost

Against §8.8's 4 MiB rows, §6.5's 64 KiB `HeadCheckProof` (bases inside it as headers), §18.4's phone budgets and the append limits, which do not change:

```text
header       tail_verdicts: ceil(tail/4) B; 256 B at the 1,024-entry fold trigger, 1 KiB at the 4,096 cap; a proof's
             64 KiB holds about 60 such headers at the cap beside their entries
rows         ProposalRow: about 100 B plus the proposed body (a SidecarAdmit about 150 B, an AdminSet 16 B a
             member) plus 20-40 B a signer; open proposals are few, bounded by their 7-day not_after: under 10 KiB
             RingRow: about 22 B; at most 4,096, so at most 90 KiB; a network at 100 statements a day holds about
             2 KiB, a Team at its 20,000-a-day limit the full 90 KiB
             ConfirmationRow: about 30 B; most devices hold none or one; 5,000 devices at three each, 450 KiB
             ProjectionSettings: under 20 B
             so rows for a 5,000-admission Team grow from about 1.3 MB (protos-bridge-row-fields' 250 B a sidecar)
             toward 1.9 MB at the worst of every column, inside 4 MiB; a personal network's rows stay under 10 KiB
time         re-application on a phone: no signature check, one parse and one effect an entry, 10-30 us each on a
             2020 phone core: under 30 ms at 1,024 entries, under 120 ms at the cap; entries after the base verify
             as today, about 60 us an Ed25519 signature plus the rule, about 100 ms a thousand; the writer's compile
             and a full reader's compile check cost what they cost today plus encoding the three lists
memory       the tail's entries while re-applying, at most 4,096 x about 600 B = 2.4 MB transient, then the
             64 KiB a phone keeps; rows decoded, 2-3x their bytes, so under 6 MB for the Team above and under
             100 KiB for a personal network; the ring as a map, 4,096 x 32 B
wire         a new device fetches what it fetched: rows and the entries from the retention point, about two fold
             spans; plus the ring and confirmations above; a base's header grows by its bitmap; rows re-upload
             only when the head or the fold moves, as before, since content addressing dedups equal rows; the
             bits change the header, never the rows, so a policy-only base at an unchanged fold uploads no rows
api          one bitmap compare and a bounded re-application per base, in place of judging the tail against a
             state it held anyway; FindStatement answers from the ring where it retains A_n, else 403 with the tip
```

### 5.5 Failure modes and recovery

```text
a lying or diverged writer     a base whose bits, rows or fold disagree with a present verifier forks that verifier,
                               which alarms (head_alarm, fork) with both pins, stops sealing in shared groups and
                               keeps the evidence; api, present at every tail, refuses the base with 403 before it
                               is sequenced, so a lie needs a compromised api as well; verifiers that started at the
                               lie agree with each other and with api, and a present verifier's HeadCheck shows the
                               split; recovery is the revocation of the writer for compromise from the base's
                               position, whose cascade parks what it admitted, and a base from another writer, which
                               forked verifiers apply once the log reverses the lie (7.9's precedence row)
a tail over the cap            api refuses the base; a writer folds through the tip and publishes again; a base
                               appended past the cap forks every reader, as a bad base does
a writer with no state at ft   a writer that started at the previous base holds its rows and StateAt from there;
                               ft is either that base's fold or at or past that base, so it always has L(ft)
a verifier that falls far      a reader whose newest pin is below the retention point cannot fetch the entries it
behind (a phone off for weeks) misses; it restarts as StartAtBase at the newest base, keeping its old pin as
                               evidence: if any pin it holds (a base's for 30 days, its last A_k) lies at or above
                               the retention point it checks the fetched chain against it; else a full reader links
                               its last A_k to the first retained entry's prev_chain through the head's records
                               (BASE records in folds), and a rows-only one trusts the base's signer as a cold gate
                               does, with the floor rule refusing any run that ends below its last pin; a mismatch
                               is head_alarm (fork), never a silent restart
a verifier holding an off-log  it forks at the activation as 7.9's precedence row says, so it checks no base's bits;
veto                           once the log reverses the activation it applies the base
site loss (TEAM-M3-02)         devices upload the verbatim entries they keep, the rows of their bases (the new
                               fields included) and pins; api adopts in position order from the oldest two members'
                               devices hold; for the first adopted base api takes its bits as a cold gate does, and
                               for every later one it compares them with the verdicts it judged on the adopted run,
                               refusing a run whose base disagrees, since such a base forked its own readers; the
                               resumed log keeps positions and digests, so no reader forks; an admin's device
                               re-seeds the config repo, whose folds hold BASE records too, and api checks the
                               newest adopted base against it as StartAtBase's anchor does; signers re-submit what
                               no adopted entry holds, open proposals among them if their rows were lost with the
                               run's base, since a proposal below the adopted run's first base survives only in rows
a reader that cannot fetch     withheld, as today: it keeps its pin, retries, and HeadCheck's proof path covers it;
rows or an entry               a rows-only run with a base whose rows the store cannot serve is refused whole
```

### 5.6 The test plan

Unit tests (sidecar root, each a top-level `func TestXxx`, fake clocks and barriers only):

```text
TestANewDeviceTakesItsBasesTailVerdicts        a new device at b holds every tail verdict from the bits and reaches
                                               S(b) byte-equal to a long-running reader's, under a head that moved a
                                               tag owner and toggled self_admit, and with a tail at below its first
                                               held position (5.1's two runs)
TestABaseWhoseBitsDisagreeForks                each of: a flipped bit, a 2 on a SidecarAdmit, a 3, a short or a long
                                               bitmap, a 1 at a BASE position forks a present reader and is 403 at api
TestATailOverTheCapIsRefusedAndForks           4,097 unfolded entries: api 403; appended, a FORK at every reader
TestAFoldedThroughBelowThePreviousBaseForks    ft between ft' and b' refused at api, a FORK if appended
TestAProposalSurvivesAFold                     k = 2: propose, base, cosign completes at a long-running reader, a new
                                               device and a rows-only gate alike; the same with two bases between
TestARecoveryWindowSurvivesAFold               a recovery proposal, a base, a tick at T_p + 72 h activates everywhere;
                                               a veto in the tail closes it everywhere; a rebind in the tail voids it
TestAVetoedProposalsReplayIsRefusedAfterAFold  the replay lands after the fold and is refused by every reader, the
                                               ring taken from rows
TestARefusedStatementResubmittedAfterItsReason a self-admission refused with self_admit off, resubmitted verbatim after
                                               a head turns it on, within 7 days: accepted alike, since the ring holds
                                               only what took effect
TestASelfAdmissionIsJudgedAlikeAtApi           a rows-only log accepts and refuses a member's own admission exactly as
                                               a full reader, under self_admit on and off; scim_signer's MemberRevoke
                                               the same once M6 lands
TestTheCascadeReadsEveryConfirmation           a stolen device's redundant OwnerConfirm of a device consented
                                               otherwise parks nothing at a rows-only gate either; an AdmissionConfirm
                                               that lifted a park pulls the device in; both from rows alone
TestReapplyRecomputesRowSignersOnTheNewRows    live_since, key_dropped_at, holders_shrunk_at and the row signer after
                                               a base equal a long-running reader's
TestAFoldHoldsItsBaseRecords                   a head missing a BASE record or holding a wrong one fails the head
                                               check; the chain recomputed from the genesis through folds equals A_ft
TestAFarBehindReaderLinksThroughTheHead        a reader with a pin below the retention point restarts, links its A_k
                                               through the head's records, and forks on a forged run
TestCompileIsDeterministicWithTheNewLists      rows vectors byte-equal on every leg with proposals, ring, settings and
                                               confirmations populated (testdata/config/rows/)
TestRowsOnlyAndFullReadersAgreeOverGeneratedLogs
                                               the existing property test extended: bases with tails, proposals and a
                                               cascade in every run; a new device started at each base agrees too
```

Schedule rows: FS-14 gains the cases above as named rows (tail verdicts taken, bits disagree, tail cap, fold rule, a vetoed replay after a fold, a self-admission at api, a far-behind reader); FS-16 gains the recovery window across a fold and a veto in a base's tail; FS-18 gains a Delegation's admission count and end carried through a fold to a new device; FS-41 gains a run whose later base's bits disagree with the adopted statements (refused) and a proposal that survives resumption in rows; FS-124 gains a presence-covered statement refused in a tail and carried as 0. §22.7's cascade list gains the confirmation-history case.

Model twins the tasks add to `AuthLog.tla` (new twin values and stories; the file's own tests are the configurations in `run.sh`): TEAM-M2-04 adds `NewestConfirmOnly` (the cascade from the newest confirmation alone, which must break Agreement between a rows-only gate and a full reader) and `DelegationEndIgnored`; TEAM-M2-05 adds `WindowFromProposalEntry` (T_p from o instead of the newest recovery signature, breaking WindowHolds) and `VoidKeepsProposal`; TEAM-M2-09 adds `WriterSkipsBaseBits` as a second lying story; TEAM-M3-02 adds a resumption story under `Adversary` where an adopted base's bits disagree. Each twin names the invariant it breaks, as the configurations here do.

### 5.7 Implementation notes, task by task

Order: the wire and the state first (TEAM-M2-04's rows, with this section's fields), then the reader (TEAM-M2-10), then the writer (TEAM-M2-09), then the rest; TEAM-M2-13 (api's sequencer) and TEAM-M2-11 (rows-only), not held, take the api checks and the bits when they next land.

**Landed code that must change** (all in the sidecar root unless said):

```text
protocol/bridge/auth.proto     ProjectionHeader.tail_verdicts = 10; ProjectionRows.proposals = 7, settings = 8,
                               ring = 9; ProposalRow, ProposalSigner, ProposalKind, ProjectionSettings, RingRow,
                               ConfirmationRow; SidecarRow.confirmations = 21; protocol/design_unfenced_test.go's
                               fence gains them and descriptor_test.go's api-7 guard their lines
protocol/config.proto          ConfigRecord.kind comment: 1 BASE allowed, body the Signed ProjectionHeader
config_state.go                ConfigState holds proposals as rows do (closed ones too, with reason and position),
                               settings from rows (Settings() loses known; SelfAdmit(), ScimSigner()); the ring
                               moves from ConfigLog into the state (a function of the log, so rows can carry it);
                               Rows() encodes the three lists
config_base.go                 applyBase: the ft rule, the tail cap, the bitmap decode and compare, then
                               reapplyTail by bits; stateFromBase keeps rows' proposals instead of emptying them;
                               configLoadRows indexes proposals, ring, settings, confirmations; foldedRecords
                               includes BASE entries; ConfigHeadCheck gains Previous = nil for a new device
config_replay.go               startAtBase: no judgeTailEntry; take the bits; the ring from rows plus the tail;
                               configTailRetentionPoint goes; a far-behind restart links through the head
config_rows_only.go            RestoreConfigLogRowsOnly and ApplyRun: unchanged in shape; the tail by bits
config_authority.go            proposals: a ProposalRow per open proposal with kind, signers (signer, at), window;
                               completion carried as verdict 2; configApplyCosign at re-application reads the row
config_apply.go                ConfigVerdict gains Completed (the 2); reapply recomputes rowSigner and ACL's fold
                               inputs on the rebuilt state; configApplyTick applies activations (TEAM-M2-05)
config_compile.go              ConfigCompileRows gains Proposals, Ring and Settings; CompileProjectionRows encodes
                               them; ConfigCompileRowsOf fills them
config_head.go                 RecordsIn and the fold parser accept kind 1; CheckConfigBase takes a new device's
                               check (Previous nil: genesis, records held, chain recomputation, settings) and the
                               settings-in-rows equality
config_retain.go               retention unchanged; the ring no longer needs its own trim once in the state
acl_statement.go (ACL's)       ReapplyStatement must take only body-derived verdict parts; ConsentedFor reads
                               confirmations; CascadeVoids reads the history (ACL's lane: raise, not edit)
sidecartest/fake_authority.go  PendingProposal(id) beside the rest, for CORE's acts
```

**TEAM-M2-04 (Delegations and the cascade).** Build first. Add `SidecarRow.confirmations` and write every AdmissionConfirm and OwnerConfirm there (kind, signer, at, lifted_park), keeping 5-8 as the newest. `ConfigState.CascadeClosure(x, since)` is 5.2.3's closure over rows: admission signers and `admitted_at`; confirmations with `lifted_park` by a signer then in P; the "adds nothing" clause from the history and §8.5's bases; bindings (`MemberRow.bindings[].signer, at`); Delegations (`DelegationRow.signer, at`, `delegation_id` on each admission, `admitted_at` from since_n for the Delegation that admitted x). Voids set `RecoveryBindingRow`'s void, `DelegationRow.ended_at`, and close recovery proposals signed by a voided binding's key (`ProposalRow` closed, reason void). `DelegationEnded` and `DelegationKeyDropped` read the row. Every effect here must be computable on a re-application from the body and the rebuilt rows (5.2.3's contract): `CascadePlan` is derived, not stored. Tests: the cascade from rows alone equals the cascade from a reader that kept every entry, over generated logs with bases between since_n and the revocation; the redundant-OwnerConfirm case through a fold. Add the `NewestConfirmOnly` and `DelegationEndIgnored` twins.

**TEAM-M2-05 (recovery in the verifier).** Proposals live in rows: `configProposal` becomes `ProposalRow` with `kind` fixed at the proposal's entry (authority; recovery-scoped with self_admit off; restored), `window_entry` and `window_time_ms` moved by each recovery-key signature. A RecoveryVeto closes the row (vetoed) at its position; voiding (a RecoveryRebind of the subject or a signing key's member, an AdminSet change, the subject's removal) closes it (voided); expiry is by the entry time at use. `configCheckTick` judges each activation from the row: open, kind, k satisfied (none needed for restored, one admission signer's cosign for recovery-scoped), `tick.time_ms >= window_time_ms + 72 h`; `configApplyTick` applies it, and `Reapply` applies it by the bits without the window check. `ConfigState.RecoveryWindow` and `PendingProposals` read rows; `HoldVeto` (an off-log veto) stays device state and forks the device at the activation as before. The re-application of a cosign or proposal with verdict 2 applies the proposed statement with the row's signers. Add `WindowFromProposalEntry` and `VoidKeepsProposal` twins.

**TEAM-M2-06 (presence).** Unchanged in substance: a presence-covered statement without its countersignature is refused at its position and carried as 0 in the next base's bits; `KeyRow` is already in rows. If decision 197 lands forwarding keys as `KeyRegister` with a new purpose, `configPresenceCovers` must not count them as presence keys. Add FS-124's "refused in a tail, carried as 0" row.

**TEAM-M2-07 (leaves, sponsors, indexers, settings).** `ConfigState.SelfAdmit()` and `ScimSigner()` read `ProjectionRows.settings`; `StaleLeafDays()` and `WitnessBoundHours()` read the head and answer unknown at a rows-only reader, which no gate rule reads. The compile writes `settings` from the head's `ServiceSettings`, and the head check compares. `live_since` and `LeafRank` are recomputed at re-application (a Suspend lifted in a tail, a device restored by a confirmation), never kept from the original check. FS-72's cases stay.

**TEAM-M2-09 (the writer).** `WriterPublishBase` as 5.2.4: L(ft) from the previous base's rows when the fold is unchanged, else `StateAt(ft)`; `compile` with proposals, ring and settings; the bits from the writer's own verdicts and the previous base's; the ft rule and the tail cap enforced before signing (fold through the tip when the tail passes 4,096, and at the 1,024-or-24 h trigger as today); on a 409, re-sign with the tail's new verdicts appended, re-compiling only when the head or the fold moved. Folds write BASE records (kind 1) in position order with the rest. The bootstrap base (version 1, ft 0) carries an empty bitmap. Tests: FS-14's writer cases plus a base after a tail of 1,024 with mixed verdicts byte-equal to a reader's expectation; a 409 that adds a refused statement to the tail; a fold holding its BASE records.

**TEAM-M2-10 (ConfigClient).** `StartAtBase` and `ApplyBase` as 5.2.4 for a full reader: the anchor on the first base (genesis, head on the repo chain through evs, fold records held, chain recomputation to the first retained entry, settings), then bits, never a judged tail; a far-behind restart as 5.5; `SidecarAuthority` gains `PendingProposal(proposalId) *ProposalRow` for CORE's acts and `Settings()` without `known`; `AddEntryCallback` fires for entries after the starting base only, with `Completed` on the verdict. Retention as today. Tests: restart at a base with a tail, equal to a reader that stayed; the anchor's refusals (another genesis, a head off the chain, a record missing, a chain that does not link).

**TEAM-M2-17 (shrink and expiry).** `holders_shrunk_at` is advanced in `Reapply` as in `Apply`, on the rebuilt rows, so a rows-only gate that started at a base reaches the same value; `ShrunkAt` equal on a new device, a gate and a long-running reader over generated logs with bases; nothing else changes.

**TEAM-M2-18 (CLI plans).** Reads `DelegationRow` and `SidecarRow` as before; the plan's "admissions left" and "ends at" come from rows that now survive any fold, and the agent plan shows a Delegation's parked agents from `parked_at` plus `confirmations` (who lifted what). No new field.

**TEAM-M2-19 (suites).** Add 5.6's unit tests that cross tasks and the FS rows named there to the T2 and T3 runs; run the admission suite with a new device started at every base and a rows-only gate restarted at every base, each compared with the long-running reader after every entry (the property the model checks, on real code).

**TEAM-M10-01 (VersioningRules and search).** No change in scope: `VersioningRules` stays head-only and read by full readers, `IndexerSet` folds to rows as today. It waits only on TEAM-M2-07 and -08.

**TEAM-M3-02 (site loss).** Uploads carry rows with the new fields and bases with bits; `AdoptConfigRun` takes the first adopted base's bits as a cold gate and compares every later base's bits with the verdicts api judges on the adopted run, refusing a run whose base disagrees; the re-seeded config repo's folds hold BASE records; the check of the newest adopted base is `StartAtBase`'s anchor at api's reach (genesis, config_pushes, records equal the adopted entries, chain recomputation); open proposals re-submitted where their rows were lost. Add FS-41's two rows and the resumption story twin.

**CORE-M3-02 (PreviewDeviceRevoke).** `Cascade` through `SidecarAuthority` is unchanged in signature; its items now come from rows' full confirmation history, so the plan lists "confirmed by" items with each confirmation's position; `ProposedSince` from retained entries as before. No scope change.

**CORE-M3-03 (RevokeDevice).** At k > 1 the act's AuthorityProposal is a `ProposalRow` the device watches through `PendingProposal`; `REVOKE_STALE` and the re-derivation are unchanged; the cosign path (`ur approve`, `Decide`) finds the proposal in S(n) after any fold, which is what this section makes true. No scope change.

### 5.8 Proposed DESIGN.md text

For the design-records track, section by section; each replaces the sentence or row named.

**§7.9, the proto block.** Add `tail_verdicts = 10` to `ProjectionHeader` with 5.2.2's comment; add fields 7-9 to `ProjectionRows` and the messages `ProposalRow`, `ProposalSigner`, `ProposalKind`, `ProjectionSettings`, `RingRow` and `ConfirmationRow`; add `repeated ConfirmationRow confirmations = 21` to `SidecarRow`'s comment ("every AdmissionConfirm and OwnerConfirm that took effect, with signer, position and whether it lifted a park, for the sidecar's life; 5-8 the newest"). Replace the ProjectionRows comment's "for the cascade a *_signer names..." with "a rows-only verifier's whole state at folded_through: for the cascade a *_signer names a sidecar_id, a recovery key's hash or a delegation_id, a *_at the position of the entry carrying the record, and confirmations every confirmation; proposals the open AuthorityProposals with their signers and windows; settings the ServiceSettings values a verifier judges by; ring the replay row's applied ids through folded_through".

**§7.9, `state` row.** "S(n) = the newest base b <= n, whose rows compile its config head, plus the STATEMENT and TICK entries among folded_through+1..b-1 re-applied in order by the verdicts b's `tail_verdicts` carries (a BASE there skipped, its rows superseded by b's), and every entry b+1..n, in order; no verifier judges an entry twice: each is judged at its own position by the verifiers then present, and every later one takes the verdict from the base that carries it".

**§7.9, `base` row.** After "config_version and folded_through are each at least the newest base's" add: "folded_through is the newest base's or at least that base's position, version - 1 - folded_through is at most 4,096, and tail_verdicts covers exactly folded_through+1..version-1 and agrees with api's own verdict at each position, a 2 only on an AuthorityProposal or AuthorityCosign; else 403 with the reason".

**§7.9, `fold` row.** Add: "a base may leave at most 4,096 entries unfolded; a writer behind that folds through the tip before it publishes".

**§7.9, `apply(e)` BASE row.** Replace "then the STATEMENT and TICK entries among folded_through+1..n-1 re-apply in order, a BASE among them skipped, its rows superseded by this base's, each keeping the verdict it got at its own position" with "the base's tail_verdicts match this reader's verdict at every tail position it judged, a BASE among them 0, else FORK; then the STATEMENT and TICK entries among folded_through+1..n-1 re-apply in order by those verdicts, a BASE skipped, a 2 applying the proposed statement with its row's signers; an effect reads only the body and the rows being rebuilt". Add to the head's requirements: "holds, as records, exactly the log's entries in (the previous base's folded_through, folded_through], bases included, each by id with its position".

**§7.9, `proposal` and `completion` rows.** Add: "rows carry every open proposal as a ProposalRow, with its signers, its window and its kind, so a cosign, veto, void or activation after a fold finds it at every verifier; a proposal closes in place at completion, veto, void or its not_after, and leaves rows at the next fold".

**§7.9, `self_admit` and ServiceSettings.** Add to ServiceSettings' signer column: "self_admit and scim_signer also compile into ProjectionRows.settings, which api and every gate judge by (§2.8 api-7)".

**§7.9, `retention` row.** Replace "so it judges every at as long-running readers do, and re-applies the statements and ticks among folded_through+1..b-1 as S(b) says" with "takes the verdict of each entry among folded_through+1..b-1 from b's tail_verdicts and re-applies them as S(b) says, judging nothing before b+1; it holds the replay ring from b's rows and the tail; a full reader recomputes A_1..A_{r-1} from the genesis through the head's records, bases included, and requires the result to equal entry r's prev_chain". Add to `retain`: "a reader whose pin falls below the retention point restarts at the newest base and links its last pin to the retained run, through the head where no held pin reaches it".

**§7.9, `cascade` row.** After "rows keep each such record's signer and position" add "and every confirmation with whether it lifted a park".

**§7.9, `site loss` `adopt` row.** Add: "a later adopted base's tail_verdicts must equal api's verdicts on the adopted run, else the run stops before it".

**§7.14.** D-TEAM-19 gains "a base carries the verdict of every entry in its tail, and its rows a rows-only verifier's whole state at its fold, so a new device and a gate reach a long-running reader's S(n) without judging a tail"; D-TEAM-20's "which every reader, a new device included, must judge alike" becomes "which every reader present judges alike and every later one takes from the next base"; D-TEAM-21 gains "open proposals ride ProjectionRows across folds"; D-TEAM-26 gains "rows keep every confirmation".

**§2.8 api-7.** The `sees` text gains: "each base header's tail verdicts (which entries took effect, which api judged itself); open authority proposals with their signers, windows and kinds; the applied-id ring; every confirmation's signer and position; and the id-level settings self_admit and scim_signer". (Pending the owner's answer to details-5-settings-in-rows.)

**§8.8.** AclRows' compile input gains "and §7.9's open proposals and ring", and the Code paragraph: "an acl statement's re-application reads only its body and the rebuilt rows".

**§22.7, §22.5's §7 row and FS-14, FS-16, FS-18, FS-41, FS-124.** The cases 5.6 names.

**§23.8.** No change: the fields freeze with §7.9's records at M2's Gn-in.

**plan-TEAM-config-head-format #1 (RESOLUTIONS).** "records run in n order with no BASE" becomes "records run in n order, BASE entries included as kind 1 with the Signed ProjectionHeader as body" (pending details-5-base-records-in-folds).

### 5.9 Owner questions

The owner answered both on 2026-11-10, each on its recommendation, and a third that a build track raised against this section's model.

**details-5-settings-in-rows** (filed; **answered: QD-629, option 1**, `self_admit` and `scim_signer` compile into ProjectionRows; TEAM-M2-07 and TEAM-M2-10 build to it). Should `self_admit` and `scim_signer` compile into ProjectionRows, where api and every gate read them, adding a §2.8 api-7 line (I-18)? Options: (1) yes, the two values a verifier judges by, nothing else of ServiceSettings; (2) every id-level ServiceSettings value, for uniformity; (3) no: api accepts every scoped self-admission and readers refuse the ones self_admit forbids, splitting api from devices. Costs: (1) two small fields and one api-7 line; the server learns a setting whose effect it already sees in which admissions land; (2) the same plus team_mail, stale_leaf_days and witness_bound_hours, which no gate judges by today; (3) a 403 for nothing and a log api sequences but devices refuse, the split D-TEAM-19 forbids. Recommendation: (1). This section is built on it.

**details-5-base-records-in-folds** (filed; **answered: QD-627, option 1**, a fold's records include the BASE entries; TEAM-M2-08, -09 and -10 landed it). Should a fold's records include BASE entries, so the config head holds every entry's body and a reader recomputes the chain from the genesis through the head? Options: (1) yes, kind 1 with the Signed ProjectionHeader; (2) no, as plan-TEAM-config-head-format #1 fills it, and a far-behind reader that holds no pin in the retained run restarts on the base's signer alone, as a cold gate does. Costs: (1) about 400 B a base in the head, one more record kind in `ConfigHead`, `RecordsIn` and `CheckConfigBase`, and a change to a fill the planning track made; (2) a full reader off the network for longer than its base pins' 30 days anchors its restart on the signer named by the rows it is restarting from, which the invite's genesis and the head's repo chain bound but no hash chain does. Recommendation: (1). This section is built on it; with (2), 5.5's far-behind row loses its chain link and nothing else here changes.

Neither question blocked the held tasks: both are additive before M2's freeze, and each task above was built on the recommendation.

**details-5-model-recovery-cosign** (raised by the team-m2-04 track; **answered: QD-628, option 1**, fix the model). §7.9 holds a statement with a recovery-key signature pending until a tick 72 h after its newest such signature, and TEAM-M2-05's code does. `AuthLog.tla` completed a recovery-signed proposal at the device cosign that brought it to k, with no window, and `WindowHolds` looked only at activated proposals, so no design run saw it. The model now returns 1 for a cosign of a recovery row and leaves its completion to the tick, `WindowHolds` also denies a recovery row that closed as completed, and the recovery cosign, `rcosign`, which only two twins' runs took, is in every run's alphabet. 5.3 records the runs. No code waited on it.

## 6. MLS group key management (§10)

Status: complete (2026-11-10)

Amended 2026-11-10 for the owner's answers: QD-641 (6.4's memory row), QD-642 (6.2.4's Recovery, steps 1 and 2) and QD-644 (the poison rule in `Gkm.tla`: 6.3's model and runs, 6.6's twin). 6.9 records every answer, QD-613 to QD-618 and these three.

Tasks held until complete: KEYS-M2-19, KEYS-M2-20, KEYS-M2-21, KEYS-M2-22, KEYS-M2-23, KEYS-M2-24, KEYS-M2-25, KEYS-M2-26, KEYS-M2-27, KEYS-M2-28, KEYS-M2-29, KEYS-M2-31, KEYS-M4-01.

Model: `sidecar/sidecartest/model/details/Gkm.tla`, its configurations (`Gkm*.cfg`, `GkmTwin-*.cfg`) and `run-gkm.sh` beside it. Questions filed: `.stack/questions/details-6-last-resort-extension.md`, `.stack/questions/details-6-welcome-pointer-key.md`, `.stack/questions/details-6-group-owner-marker.md`, `.stack/questions/details-6-claim-key-prefix.md`, `.stack/questions/details-6-ladder-aad-widths.md`, `.stack/questions/details-6-reform-epoch-zero-floor.md`.

### 6.1 The problem

§10 keeps one MLS group per repo and, above it, one key generation chain. Three things move it: commits, which make epoch n from epoch n-1 by one If-None-Match create of `epoch/<n>`; rotations, which make generation g+1 from g by one If-None-Match create of `gen/<g+1>` after every delivery of RK_{g+1} is staged; and the authorization log, which every device reads at its own pace and which decides, at each position, who holds the key (`KeyHolders`, D-KEYS-16). Several devices of several members commit and rotate at once; a device's log position (its tip), its MLS epoch and its newest generation each lag the others' by hours or weeks; deliveries are written by whoever is online and read whenever the recipient returns; devices lose their state and come back by resync or by the member's recovery code. The requirement is fourfold: every member device converges on one group state per repo and epoch; no removed member reads a later generation or anything sealed after its removal; no device loses access it is entitled to; and every refusal is safe and recoverable.

The text as written is close, and most of it stands. Four places are wrong or open, each with a scenario, and three choices wait on the owner:

**A last-resort KeyPackage's Welcomes collide (question keys-m2-13-last-resort-welcome-pointer).** `gkm/welcome/<sidecar_id>/<ref>` keys a Welcome pointer by the KeyPackageRef the Add used. A one-time KeyPackage serves one claim, so its ref names one Welcome; the last-resort KeyPackage serves every claim once the one-time ones are gone (§10.6: "never deleted") and is the only one a device with 128 claims outstanding, or a device offline past its refill, has left. Device E, its one-time KeyPackages exhausted, is added to repo B on Monday and to repo A on Tuesday, both through its last-resort KeyPackage, before it comes online. Both Adds write a pointer at `gkm/welcome/E/<lr-ref>`: with If-None-Match the second is refused and A's Welcome is unreachable; with an overwrite B's is. The committer cannot tell, and E never joins that group: §10.6's "a writer leaf removes and re-adds the joiner after 10 minutes" fires only when the uploader crashed before writing the Welcome, and here the Welcome exists. E, an entitled reader, reads nothing of that repo until some unrelated Remove and re-Add happens. The landed `gkmservice/welcomes.go` keeps the standing pointer and alarms, which is the right interim, and the model's `GkmTwin-PointerByRef` reaches the lost Welcome in five steps.

**A GroupForm can name another repo's group (question keys-m2-12-groupform-names-anothers-group).** gkm ties a group to its repo only through `gkm/repo/<repo_id>/<seq>`, and a group route names only the group, which gkm resolves to the repo among the token's scopes whose newest form names it. A member who reads repo A (r) and administers repo B (admin) learns A's group id from A's heads, files a GroupForm for B naming it, and B's `rw` now reaches A's group: it can occupy `gen/<g+1>` with a claim A's members refuse (§10.9), which wedges A's rotations and so its write gate until a re-form, and it can post commits to A's epochs. Nothing leaks (every object there is ciphertext), but a reader holds a write position in another repo's group, and which repo a process resolves depends on which forms it read first. The landed `groups.go` refuses a form naming a group that already has objects, one LIST per form; that still leaves the race between A's form and A's `epoch/0`, in which B's form lands first and the resolver sees two newest forms naming one group. `GkmTwin-FormsUnchecked` shows the claim by a non-writer.

**A commit can carry the REMOVE generation into a tree that still holds the removed leaf.** §10.5 lets a wrapped writer rotate for a removed leaf X "by ReaderWraps to every remaining leaf" while no leaf has committed the Remove, so that no repo stays gated while every leaf is offline; §10.6's epoch PUT check makes every commit carry `GenWrap_n` of gkm's newest generation; and §10.4 has every leaf, read_only ones included, commit a path-only self-update every 7 days (30 above 50 leaves). Put together: agent D rotates to g+1 after member device X is revoked, wrapping RK_{g+1} to leaves A and C; the tree at epoch e still holds X; C, a read_only page Worker whose self-update is due, commits a path-only commit at e+1 carrying GenWrap_{e+1} = seal(KEK_{e+1}, RK_{g+1}). X's leaf is in e+1's tree, so X derives KEK_{e+1} from the commit (which gkm serves to any reader token, and which a copy of the ciphertext serves to anyone) and opens RK_{g+1}: the generation that exists to exclude X. §10.9's roster row ("every commit's roster lies within the key holders at its auth pin") forbids the commit, and §10.6's leaf row forbids C the Remove it would need, but nothing tells C to wait, and the two readings a builder is left with are a leak (C commits, members adopt) or a stall (members refuse C's commit, which then stands at `epoch/<e+1>` as the epoch every later commit must build on). The same shape blocks every resync (an external commit "removes at most its own old leaf") while a dropped leaf stands. `GkmTwin-GenWrapIgnoresRoster` reaches the leak in five steps.

**A re-formed group's epoch 0 has no auth pin (question keys-wire-reform-epoch-zero).** A re-form's generations arrive after its form, through the ladder, so `POST /gkm/repos/<id>/forms` has no GenRotate to read epoch 0's pin from, and the landed `epochs.go` refuses every commit onto a pinless epoch. A re-formed group takes no commit at all until this is settled, which blocks KEYS-M2-25 and FS-6's re-seed.

The three choices the brief names are settled in 6.2.2: which extension marks a last-resort KeyPackage (keys-m2-07-last-resort), which Welcome a device gets when two share a last-resort KeyPackage's pointer key (the first failure above), and group-id uniqueness across repos (the second). Beside them, 6.2.2 fixes what else the tasks would otherwise have to decide: the ladder's AAD widths and generation 1's cause (keys-ladder-aad-widths), the claim key's prefix (keys-m2-13-claim-key-prefix), the data each flow persists and the names of every new object, field and setting.

Three further rules that the text states but spreads over four places, each of which the model shows a violation without, are gathered in 6.2.3: a claim's auth pin never falls below its parent's (§10.6's claim checks), a LATE delivery is signed at a state at or past its generation's pin (§10.9's late row), and a leaf_wrap uses only an epoch whose tree holds holders alone (§10.5's remove row). `GkmTwin-ClaimBelowParent`, `GkmTwin-LateBelowClaimPin` and `GkmTwin-LeafWrapDirtyTree` each break one and reach a removed leaf reading the generation that excludes it; `GkmTwin-NoGate` seals past a shrink; `GkmTwin-SelfJoinCarriesGenWrap` lets a recovered device's self-join hand the lost device's leaf the next generation.

### 6.2 The design

#### 6.2.1 The principle

**Every secret of a generation reaches a party by exactly one of four paths, and each path is fenced by one object that a verifier can judge at its own pin.** RK_g reaches a leaf through a GenWrap in an epoch object, through a leaf_wrap in `gen/<g>`, through a STAGED delivery written before `gen/<g>`'s claim, or through a LATE delivery written after it; a non-leaf only through the last two, and a member's recovery code through its RecoveryWraps. The four fences are: (1) *the roster rule*, that every commit's new tree lies within `KeyHolders` at the commit's auth pin, which the committer checks before it commits and every member checks before it adopts, so that no epoch object ever wraps a generation to a tree holding a party that generation excludes; (2) *the claim chain*, that `gen/<g+1>`'s auth pin and time are at or past `gen/<g>`'s, so that holders only ever shrink along the chain; (3) *the delivery pin*, that a STAGED delivery is judged at its claim's holder set and a LATE one at its signer's state, which is at or past the claim's; and (4) *the leaf_wrap condition*, that a leaf_wrap's epoch holds holders alone. With these, "removed reads nothing new" is a property of the store, whatever any honest device's timing, and the model's `RemovedReadsNothingNew` checks exactly that over the reach a removed party has when it fetches everything.

Two consequences shape the flows. A leaf that may not commit a Remove (a read_only leaf; any external commit) **waits** while its tree holds a dropped leaf, and a hint keeps writer leaves awake until one commits it. And every refusal a member makes of a commit is a refusal to *adopt*, never a fork: the object stands at gkm, members alarm, and the group is repaired by a Remove of the committer and a rotation, or by a re-form, as §10.9 says; so the committer-side check must be the one that normally runs, and the member-side one the backstop.

Convergence needs no new mechanism: `epoch/<n>` and `gen/<g>` are each one If-None-Match create chained on its predecessor, every member adopts its own commit only on gkm's 200 and another's only from the stored object, and the generation pin and epoch pin never fall at any device. What this section adds is the set of preconditions under which a device *makes* each object, so that honest devices never write one that others must refuse.

#### 6.2.2 Formats settled

Each is a format change before M2's freeze (owner decision 194), with its §2.8 line where a server reads it; 6.8 gives the lines and 6.9 the questions.

**Last-resort KeyPackages** carry draft-ietf-mls-extensions' `last_resort` extension, type 0x000A, empty `extension_data`, in `KeyPackage.extensions` only, and every leaf lists 0x000A and 0xF553 (`ur_group`) in `capabilities.extensions`. gkm reads the flag from the KeyPackage it stores (`MlsKeyPackageInfo.LastResort`), never from the route. Two rules RFC 9420 §16.8 implies become ours: a device that joined through its last-resort KeyPackage commits a path-only self-update at its first opportunity after the join (the leaf's HPKE key is shared with every other Welcome that package serves until then), and replaces the last-resort KeyPackage at its next upkeep pass; and a device takes its last-resort KeyPackage's Welcomes under I-16's rule alone (no join at or below the newest epoch it reached of the group), which `mls_engine.go` already keeps. As built in `mls_extension.go` (keys-m2-07-last-resort option 1; question details-6-last-resort-extension).

**Welcome pointers** are keyed by group and epoch, never by ref: `gkm/welcome/<sidecar_id>/<group_id>/<n>`, n 20 digits as every epoch number, group_id 32 lowercase hex (QD-442). `GkmWelcomePointer` gains `bytes key_package_ref = 3`, the ref the Add used, so a joiner opens the Welcome with the KeyPackage that ref names and the reader needs no other lookup. One Welcome, one key, whatever KeyPackage it used. `GET /gkm/welcomes` lists the prefix `gkm/welcome/<sidecar_id>/` as it does now and answers each pointer with its Welcome; a device holding several pointers for one group takes the one with the highest n above the newest epoch it reached and skips the rest, since a lower one names a leaf a later Remove took out (the 10-minute re-add) or an epoch below its pin. The reconciler deletes a pointer at its recipient's first ack past n, at most 90 days, as it does today. (keys-m2-13-last-resort-welcome-pointer option 1; question details-6-welcome-pointer-key.)

**A group belongs to one repo from its first byte.** The first write of a creation or a re-form is the group's owner marker, `gkm/<group_id>/owner`, created If-None-Match, holding `GkmGroupOwner{bytes repo_id = 1; bytes network_id = 2}`, written by gkm from the token; a marker that exists with other bytes answers 409 and nothing else of the request is written; equal bytes resume a crashed request. Only then come the form, `epoch/0` and, for a creation, `gen/1`. gkm resolves every group route through the marker: `GET gkm/<group_id>/owner` (immutable, cached for the process's life), the repo it names must be among the token's scopes, and that repo's newest form must name the group; a token naming no such repo is refused whatever its other scopes. The shred deletes the marker with the group's other objects, and a re-seed's form in §19.10's deleted mode writes it again. The LIST the landed `groups.go` makes before a form goes. Group ids stay 16 random bytes (plan-KEYS-reform-ladder's rule 1 stands). gkm-1's §2.8 row, which already shows (repo_id, group_id) pairs, gains the marker in words; it discloses nothing new. (keys-m2-12 option 1's intent, made race-free; question details-6-group-owner-marker.)

**The ladder's AAD widths** are as built: `u64be(g)` and `u64be(e)` wherever §10.5 writes g or e, one byte for `cause`, so GenLink's AAD is `repo_id || u64be(g) || u8(cause)` (25 B), GenWrap's and LeafWrap's `group_id || u64be(e) || u64be(g)` (32 B) and GroupInfo's `group_id || u64be(e)` (24 B); `gen/1` carries cause REQUEST (2), and a reader refuses REMOVE there. `testdata/gkm/ladder.json` pins the bytes. (keys-ladder-aad-widths option 1; question details-6-ladder-aad-widths.)

**The claim key** `gkm/kp/<sidecar_id>/<ref>.claim` stands, and §11.8's "no key prefixes another" means a *path* prefix (an existing key followed by `/` at the new key's next byte, or the reverse), MinIO's real constraint; `sidecartest/fake_blobs.go` checks that, and KEYS-M2-13's filter of the one byte-prefix report goes once it does. (keys-m2-13-claim-key-prefix option 1; question details-6-claim-key-prefix.)

**A re-form's epoch 0 carries no auth pin**, as `GkmGroupReformRequest` landed; gkm gives epoch 1's pin its floor from `gen/<form.generation>`'s auth, which the ladder must have written before the group takes any commit (plan-KEYS-reform-ladder rule 5), so the epoch PUT check reads "never below the previous epoch's pin, or, for epoch 1 of a re-formed group, below gen/<the form's generation>'s". (keys-wire-reform-epoch-zero option 1; question details-6-reform-epoch-zero-floor.)

**Names.** New settings in `GkmSettings` (client): `PendingCommitDelay` (15 s plus jitter, KF2/KF3's other writers), `WelcomeTimeout` (10 min, the re-add), `LateAskInterval` (1 min), `LateDeliverJitter` (0-15 s), `SelfUpdateInterval` (7 d) and `SelfUpdateIntervalLarge` (30 d, above `LargeGroupLeafCount` 50), `ScheduleInterval` (30 d), `ResyncReplayMax` (100 epochs), `RotateBatchSize` (256) and `RotateBatchConcurrency` (4), `SeatCount` (1,000). In `GkmServiceSettings`: `PendingHintInterval` (60 s), `DroppedLeafHintInterval` (60 s, 6.2.3's hint), `GroupInfoPointerLagCount` (16). Keychain items in `keychain.ur` (§5.9): `gkm/<repo_id>/gen/<g>` (RK_g and the Signed GenRotate, per plan-KEYS-reform-ladder rule 2), `gkm/<repo_id>/draft` (a rotation's RK' and GenRotate draft), `gkm/<repo_id>/pins` (6.2.6), `gkm/<repo_id>/pending` (6.2.4's pending-change record), and the MLS state files KEYS-M2-09 keeps.
#### 6.2.3 The rules

Notation: `S` this device's newest verified state at tip `n`; `H(n, t) = KeyHolders(R, S(n), t)`; `tree(e)` the leaves of epoch e; `g*` gkm's newest generation and `gen/<g>.auth`, `.time` its claim's pin and time; `shrunk(n)` = `holders_shrunk_at` at `S(n)`; `expiry(t)` the newest holder expiry at or before `t`; `covers(g, n, t)` = `gen/<g>.auth.version >= shrunk(n)` with the pin on my chain and `gen/<g>.time >= expiry(t)` (§7.9's coverage, as `GkmGenerationCovers` has it).

```text
R1 judged pins    a device judges a commit at its header's auth, a claim at its auth and a STAGED delivery at
                  its claim's, a LATE one at its own auth (§10.9's judged row); one above n waits (never a
                  refusal), one off the chain is a fork alarm, one before my previous base is not judged
                  and counts against no one; a device builds nothing on an object it has not judged: it
                  commits only at the newest epoch it adopted, rotates only from a generation it holds and
                  judged, and delivers only a generation it holds and judged
R2 pin floors     a commit's auth is at or past the previous epoch's and the carried generation's; a claim's
                  auth and time are at or past its parent's; a LATE delivery's auth is at or past its
                  generation's; gkm refuses what it can see of these (the epoch PUT and claim checks, the
                  wrap checks' late row), members refuse the rest; so holders only shrink along each chain
R3 roster         every commit's new tree lies within H(auth, time) at its own header, but a recovery self-join
                  with generation 0, which may leave the lost devices' leaves; the committer checks this
                  before it commits, and carries every Remove it may commit that the rule needs (the pending
                  engine, 6.2.4); a member refuses a commit whose tree breaks it and never adopts or
                  encrypts to its epoch, raising refused (plan reading 7), and the group repairs as §10.9's
                  "a bad commit can stall" says; a leaf that may not commit a Remove (read_only; an external
                  commit, which removes only its own old leaf) waits while its tree holds a dropped leaf,
                  self-updates and resyncs included, and hint H1 keeps a writer leaf awake until it commits
                  the Remove
R4 GenWrap        a commit's GenWrap wraps g*, which the committer holds and judged, under the new epoch's
                  KEK; with R3 that epoch's tree holds holders of g* alone (g*'s holders are H at its claim,
                  and the commit's auth is at or past it by R2); the one exception is the generation-0
                  self-join, which carries none
R5 leaf_wrap      a rotator uses a leaf_wrap under KEK_e only if it is a leaf of e and tree(e) ⊆ H at its
                  state; else every leaf of e in H gets a ReaderWrap, as every agent does; an epoch whose
                  tree holds a dropped leaf never carries a leaf_wrap, and no later epoch wraps g+1 into
                  that tree (R3, R4)
R6 delivery       a STAGED delivery's recipient is in the claim's holder set, and a LATE one's in H at the
                  signer's auth and time, the signer a holder that is not read_only and whose auth is at or
                  past gen/<g*>'s; a LATE delivery names a key the recipient published and gkm serves; a
                  delivery valid at its own state stays valid (§10.9's history row)
R7 gate           a writer seals to the newest generation it holds only while that generation covers
                  shrunk(n) and expiry(now) at its state, and evs passes the push only while it covers them
                  at evs's state (§10.6, §11.8); EnsureWritable rotates first when it does not; a depositor
                  seals to a drop key under the same coverage (D-KEYS-17)
R8 one tree       a device adopts its own commit only on gkm's 200 and another's only from epoch/<n> as
                  stored; its epoch pin (group_id, n, epoch_authenticator) and generation pin (g, C_g) never
                  fall, and no join, Welcome or external, takes it to an epoch at or below the newest it
                  reached (I-16); HeadCheck compares both pins (6.2.6)
```

Why R3 is checked by the committer and not only by members: a bad commit leaks the moment it stands at `epoch/<n>`, since the removed leaf, or anyone holding the ciphertext, derives KEK_n from it whatever honest members do; a member's refusal contains the damage (it treats the carried generation as poisoned: never seals to it again, rotates at once with cause REMOVE, and the next leaf commit removes the committer, §10.9's poisoned row) but cannot undo it. Every honest leaf therefore runs the same check before it commits, and the model's twin shows what the text's self-update interval alone would do.

Hints (§10.6's duties, extended):

```text
H1 dropped leaf   the reconciler hints pending every DroppedLeafHintInterval to a repo's writers while gkm's
                  newest verified state shows a holder dropped since the newest epoch's auth pin and time, as
                  it already does while the gate is closed; gkm cannot see whether the dropped holder was a
                  leaf, so the hint is sent either way and costs one wake a minute per affected group; it
                  stops at the first epoch whose pin passes the drop
H2 waiting leaf   a leaf that waits under R3 asks GET .../group-info?want=<e+1> at most once a LateAskInterval,
                  which hints wrap-pending to the writers as an older want does (KF5); a writer so hinted
                  runs EnsureWritable's commit step
H3 pending        as today: pending to the writers, the statement's signer first, at each holder change,
                  every PendingHintInterval while the gate is closed; in the directory group to the signer
                  and the config writers only (D-KEYS-23)
```

#### 6.2.4 The flows as state machines

Each flow is a machine per (device, repo); every transition names the object it writes and the check that fences it. `persist` means a keychain write under §5.9's AEAD before the next step, so a kill resumes from it. Pseudocode is the implementer's: Go names from the plan (`gkm_*.go`), fields from `protocol/gkm.proto`.

**The pending engine** (KEYS-M2-21), one per group, single-flight, drives every membership change. Its input is the log applier's `AuthAdvanced(S)` and gkm's hints; its state is derived, never stored but for the Welcomes it owes:

```text
Pending(S, e) for a leaf of epoch e, tree(e), H = H(n, now):
  removes   = tree(e) \ H                                    (every dropped leaf; R3)
            ∪ {x ∈ tree(e) : x not leaf-entitled at S}        (config and directory groups: §7.9's move)
            ∪ {x ∈ tree(e) : stale(x)}                        (§10.9's stale row, KEYS-M2-19's one function)
  adds      = {d ∈ H ∩ member devices : d ∉ tree(e), d leaf-entitled (config, directory) or seated
              (data: earliest-admitted first up to SeatCount), d has a KeyPackage gkm serves, d consented
              where the kind is owner-bound (§8.5), d anchored if a restored binding admitted it (§10.8)}
  welcomes  = Welcomes this device committed whose pointer it has not yet written
  rotate    = ¬covers(g*, n, now) ∨ gen/<g*>.time + ScheduleInterval < now ∨ a request is pending

may(c)      c commits removes and adds iff c is a writer leaf (not read_only, not wrapped); the admission's or
            revocation's signer may in the config and directory groups (owner decisions 128, 182); the
            granting device first, other writer leaves after PendingCommitDelay; a wrapped writer commits
            nothing and rotates (6.2.4's Rotate) or writes first wraps (KF2)

Run(c):     while Pending ≠ ∅ and may(c):
  1  if removes ∪ adds ≠ ∅: Commit(removes, adds)             one commit carries all of them (R3)
  2  write each owed Welcome and pointer                       welcome/<n>, then welcome/<d>/<group>/<n>
  3  if rotate: Rotate()                                       6.2.4's Rotate
  4  refetch S and gkm's newest epoch and generation; loop
```

**Commit** (any leaf; the engine's step 1, a self-update, a resync's or self-join's external commit):

```text
states   Idle → Staged(commit, e+1) → Uploading → Adopted | Discarded
pre      at the newest epoch e I adopted; tip n ≥ epoch/<e>.auth and ≥ gen/<g*>.auth; I hold RK_{g*} (R1);
         new tree ⊆ H(n, now) (R3), or the self-join exception; path = true for every commit but an Add-only
         one; read_only: path only, no proposal; an external commit: ExternalInit, my old leaf's Remove, a path
stage    engine.Commit(args) → staged; header {generation g*, auth (n, A_n)} in authenticated_data; seal
         GenWrap_{e+1} = seal(KEK_{e+1}, RK_{g*}; group_id || u64be(e+1) || u64be(g*)) and, at ≤ 16 leaves,
         GroupInfo_{e+1} under K_groupinfo of g*, group_info_generation = g*; persist nothing (a staged commit
         that dies is remade)
upload   POST epochs/<e+1> {commit, gen_wrap, sealed_group_info, group_info_generation}
         200   Adopt; pins ← (e+1, epoch_authenticator), (g*, C_{g*}); if Adds: owe the Welcome (persist
               welcomes owed with the Welcome bytes and recipients, keyed by (group, e+1)); hint commit rides
         409   Discard; Process(winner) as any received commit; rerun Pending (KF6)
         403   refused by gkm's checks (rate, pin, header): alarm refused if my checks passed; wait for S
         unknown  GET epoch/<e+1>: mine (same commit bytes) = 200; another = 409; 404 = repeat the POST
welcome  POST welcome/<e+1> {welcome, recipients [(sidecar_id, ref)]}; gkm writes welcome/<n> If-None-Match,
         then a pointer per recipient If-None-Match, equal bytes answering success; a crash before this step
         leaves joiners waiting: a writer leaf that sees no welcome/<e+1> after WelcomeTimeout removes and
         re-adds them (the engine's removes gain "added at e+1 with no Welcome after WelcomeTimeout")
```

**Process** (a received commit, from `GET epochs?after=` or a commit hint):

```text
pre      epoch/<e+1> stored; tip n ≥ its header's auth (else wait: R1)
check    engine.Process(bytes) stages it (signature, proposals, path, confirmation tag: mls_group.go); then
         §10.9's committer and check rows at the header's auth: the committer may make it (Add: a writer leaf
         or the signer; Remove: a writer leaf or the signer, never the target; path-only: any leaf; external:
         the sidecar itself, resync or self-join); each Add's credential admitted, pinned, consented, seated
         or entitled; each Remove's input (a revocation, park, Suspend, grant end, entitlement loss, or a
         stale leaf by the credential's not_after rule); the new tree ⊆ H at the header (R3) but a
         generation-0 self-join; header.generation = the previous epoch's or newer, and its GenWrap opens to
         RK matching gen/<g>'s C_g (or none at generation 0)
adopt    Adopt(); pins forward; if removed: leave the group (at ← none), keep every RK_g held, read on by
         wraps if still a holder (a stale-removed or wrapped device), else by nothing new
refuse   alarm refused naming the committer and epoch; never adopt; keep processing nothing of this group
         until a later epoch's chain shows the group repaired (a Remove of the committer and a rotation, or a
         GroupForm); seal nothing to the generation its GenWrap carried (poisoned, §10.9)
```

**Rotate** (KEYS-M2-20; §10.5's five steps, with every fence named):

```text
states   Idle → Drafted(RK', GenRotate) → Staging(k of W) → Claiming → Done | Lost(winner)
pre      I am a writer (or the statement's signer, config group), a holder or covered at S; I hold RK_{g*} and
         judged gen/<g*> (tip n ≥ its auth); GET gen/<g*+1> → 404
1 draft  H = H(n, now); RK' random; C' = SHA-256("UR evs 1.0 commit" || repo_id || u64be(g*+1) || RK');
         GenLink = seal(K_link', RK_{g*}; repo_id || u64be(g*+1) || u8(cause)); cause = REMOVE iff
         GkmRotationRemoveRequired (a shrink, expiry or compromise retirement since gen/<g*>'s pin and time,
         or a poisoned parent), else REQUEST or SCHEDULE; holders_sha256 over H's identities; drop key if the
         kind takes deposits (drop_not_after_ms = time_ms + DropKeyLifetime); persist draft {RK', GenRotate}
2 set    W = deliveries:
           leaves      if I am a leaf of my epoch e and tree(e) ⊆ H: leaf_wrap {e, seal(KEK_e, RK')} in the
                       GenRotate (R5); else a ReaderWrap to each leaf of e in H, to the ReaderKey gkm serves
                       for it if 10.5's readerkey check passes (time_ms < not_after ≤ time_ms + 7 d + 10 min)
           wrapped     config and directory groups: each member device in H outside tree(e): a ReaderWrap
           agents      each agent in H not covered by a live Delegation in H: a ReaderWrap
           delegations each live Delegation in H: a DelegationWrap to its reader key
           recovery    each member reading R with a current binding: a RecoveryWrap at its b8
         wrap_count = |W|; every delivery STAGED at wrap/<g*+1>/<c8>/<recipient>/<k8> and recovery/.., in
         batches of RotateBatchSize, RotateBatchConcurrency at once (QD-066); a 412 with equal bytes is
         success, with other bytes an alarm (another rotator with my C', impossible unless RK' leaked); a 0
         item is sent again; persist nothing between batches: a restart re-stages (If-None-Match makes it
         safe) and stale staged objects of a lost claim are GC'd after 24 h
3 claim  POST gen/<g*+1> (the Signed GenRotate), the linearization point; testHookBarrier around it
         201   Done; keychain gen/<g*+1> ← {RK', bytes}; pin (g*+1, C') forward; delete the draft; seal to
               g*+1 from now
         412   winner = the stored GenRotate: judge it (§10.9's rotation checks at its auth: signer, chain,
               holders recomputed at its pin and time, each STAGED delivery I can read, cause, time);
               if it passes and covers(g*+1, n, now) and I have a delivery or leaf_wrap to open: adopt it
               (keychain, pin), delete the draft, Done; if it passes but does not cover what I rotate for:
               fetch my key of it (a late ask if none), then go to 1 at g*+2; if it fails: poisoned (alarm,
               never seal to it, rotate at g*+2 at once with cause REMOVE, and the admins revoke its signer)
         403   my state is behind gkm's (signer, auth or time check): refetch S and retry at 1; a time
               refusal waits for my clock
         unknown  GET gen/<g*+1>: my C' = 201; another = 412; 404 = repeat the POST with the same bytes
```

**Late delivery** (KEYS-M2-20, the deliverer; KEYS-M2-22, the asker):

```text
asker    a holder whose GET wraps/<g*>?recipient=&want=<my k8> finds no delivery of g* to a key it holds: ask
         with since = first ask, at most once a LateAskInterval; a device none of whose keys opens anything
         publishes a fresh ReaderKey first (upkeep); meanwhile it reads with what it holds, and a leaf keeps
         processing epochs (a GenWrap of g* in any epoch it adopts also serves)
deliver  on wrap-pending naming recipient x: wait LateDeliverJitter; require: I am a holder (or covered), not
         read_only, hold RK_{g*} and judged gen/<g*>, tip n ≥ gen/<g*>.auth (R2), x ∈ H(n, now) (R6); GET
         reader-key/<x> (or the Delegation's key): 10.5's readerkey check; PUT one LATE KeyDelivery at
         wrap/<g*>/<c8>/<x>/<k8> with auth (n, A_n) and time_ms = max(now, gen/<g*>.time_ms); 201 done; 412:
         judge the winner (delivery checks); 409 (not newest, or a key gkm no longer serves): refetch and
         retry once; unknown: repeat the PUT (If-None-Match)
```

**KF1, create** (KEYS-M2-21):

```text
states   Filed(RepoCreate) → Placed(keying) → Owner → Form → Epoch0 → Gen1 → Staged(k of W) → Active → FirstAdd
1        file RepoCreate (§8.8); evs creates repo/<id> keying and place/<id> (§11.8); persist nothing yet
2        draw group_id (16 random bytes), RK_1, GenRotate_1 {generation 1, no parent, cause REQUEST, auth (n,
         A_n), holders_sha256 over H(n, now), wrap_count}; engine.CreateGroup(group_id, ur_group {network,
         repo, kind, owner}); seal GenWrap_0 and GroupInfo_0 under RK_1; persist draft {group_id, RK_1,
         GenRotate_1, MLS state}
3        POST /gkm/groups {form, gen_rotate, gen_wrap, sealed_group_info, cipher_suite}: gkm writes owner,
         form, epoch/0, gen/1 in that order, each If-None-Match, equal bytes resuming (QD-464); 409 on
         other bytes at the owner marker: the id is taken, draw another at 2
4        stage generation 1's deliveries as Rotate's step 2 (ReaderWraps to agents and, in the config and
         directory groups, to member devices in H; DelegationWraps; RecoveryWraps); while the repo is keying
         gkm accepts STAGED deliveries of generation 1 by gen/1's signer (§10.6's wrap checks)
5        POST /evs/v1/repos/<id>/activate (RESOLUTIONS plan-EVS1-repo-activate-route): only after 4, so no
         content predates its recovery wraps (D-KEYS-18); then delete the draft, keep gen/1 in the keychain
6        the engine's first run adds every pending member device in one Add commit (KF2)
crash    before 3: resume from the draft (same bytes); between 3 and 5: resume at 4 (the repo is still
         keying, the group exists); the creator's only device lost before 5: the repo stays keying forever
         (FS-20), and a repo admin's device may re-form it or delete it
```

**KF2, add a device D; KF3, add a member** (the engine's adds):

```text
D        enrolls; SidecarAdmit lands at n_a; uploads ReaderKey and, as a member device, KeyPackages (a device
         a restored binding admitted: ReaderKey only until anchored); gkm hints pending at its first upload
         and at each state that lists D as a reader
leaf     a writer leaf (the granting device first; the signer in the config and directory groups) claims a
         KeyPackage (POST key-packages/claim; 404: D has none yet, D reads by first wrap where the group
         wraps, else waits) and commits the Add with every other pending change; the Welcome and pointer
         follow; D joins: JoinWelcome, open GenWrap_n for RK_{g*} against gen/<g*>'s C_g, open GroupInfo_n
         under K_groupinfo of group_info_generation, Complete; walk the ladder down to generation 1; pins
         start at (n, epoch_authenticator) and (g*, C_{g*}); D acks
wrapped  an agent, or in the config and directory groups a member device that is wrapped or has no
         KeyPackage: a LATE ReaderWrap of g* from any holder but a read_only one, hinted writers first, signed
         at a state listing D (R6); a covered agent reads at once through its Delegation's wrap
seat     data repos: at most SeatCount leaves; the engine fills a free seat with the earliest-admitted waiting
         device that has a KeyPackage (§8.12); the 1,001st waits keyless, named in the writer's preview
consent  owner-bound kinds: an unconsented D is parked (no Add, no wrap) and raises approval_pending (§8.5)
member N a grant or EvsShare for N lands; KF2 runs for each of N's devices
```

**KF4, remove X** (the engine's removes, then Rotate):

```text
1  entry n' revokes X (or a grant ends, a park, a Suspend, an expiry at T_e): holders_shrunk_at = n' (or
   expiry(T_e)); evs refuses pushes whose generation does not cover it (412 GATE_CLOSED), gkm hints pending
2  a writer leaf, the revoking device first, commits Remove(X) with a path (R3) at auth ≥ n'; a wrapped
   revoker (config, directory) skips to 3 and the next leaf commit removes X (H1 keeps leaves awake)
3  any writer rotates: a leaf whose tree is clean by leaf_wrap under KEK_{e+1}; a wrapped writer, or a leaf
   whose tree still holds X, by ReaderWraps to every remaining leaf and agent (R5); cause REMOVE
4  the gate reopens for writes declaring g+1 (R7); EnsureWritable runs 2 and 3 for a writer before its next
   write, so reaps and expiries batch (D-KEYS-6)
5  §11.7's next write of each file is a full checkpoint, and a path epoch is due (§11.6)
```

**KF5, catch-up and resync** (KEYS-M2-23):

```text
behind   ≤ ResyncReplayMax epochs: Process each in order (the Adopt chain)
resync   further behind, or commits pruned, processing failed, or my leaf was removed as stale: open the
         current sealed GroupInfo (inline at ≤ 16 leaves, probing epoch/<pointer+1>.. to a 404; above, the
         group-info object, a ?want= hinting a leaf to write it) with K_groupinfo of the generation it names,
         which I hold or ask for late; then an external commit at g* (R1-R4: tip ≥ epoch/<e>.auth and ≥
         gen/<g*>.auth; tree(e) \ {my old leaf} ⊆ H, else wait under R3 and ask H2); else await a re-add or
         use the recovery code
```

**KF6, concurrent commits:** the 409 loser discards its staged commit, having written no Welcome, processes the winner (Process) and reruns Pending; two rotations race only at `gen/<g+1>` (Rotate's 412). **KF7, gkm unavailable:** `CurrentRepoKey` and `RepoKey` answer from the keychain, `DropKey` from the newest GenRotate held if it still covers at my state (R7), writes continue while every shrink is covered (evs checks the gate from the log) and stop at the first uncovered one until gkm returns; joins, catch-up, rotations and deliveries wait and retry on the hint intake's resync.

**Recovery** (KEYS-M2-24; §10.8 with its order made explicit):

```text
states   Fetching → Admitted → Anchored → SelfJoined(config) → Joined(others) → Revoking → Rotated
1        under recovery:<member_id>, GET recovery/<member_id>/wraps: fetch the newest per group whose b8 is my
         binding's and keep each in the keychain, unopened: a wrap opens only against gen/<g>'s C_g, all 32
         bytes of which its AAD holds, the reply carries 8 of them, and this scope reaches no gen/ route;
         read the log and these wraps only (question keys-m2-24-recovery-wrap-opens-before-admission, QD-642)
2        admitted (§7.9's table), so gen/<g> reaches me: open the config group's RecoveryWrap against
         gen/<g>'s C_g, then §7.9's anchor on its RK_g: head_alarm (fork) and stop on failure; only then open
         every other group's wrap the same way, judge its generation and walk its ladder
3        self-join the config group and every group M writes by external commit: if tree(e) ⊆ H at my tip,
         generation g* with its GenWrap (an ordinary resync); else generation 0 with no GenWrap (R4's
         exception), the lost devices' leaves staying; join the others through KF2 (upload KeyPackages)
4        revoke M's lost devices (§5.6's calls); then, as a writer leaf, the engine's next Commit removes
         every dropped leaf (R3), then Rotate (cause REMOVE); the self-join's epoch gave them nothing, and no
         generation after their revocation is wrapped into a tree holding them
restored a binding a void restored: ReaderKey, no KeyPackage, the late ReaderWrap of the config group's
         current generation (KF2's wrapped row), the anchor on its RK_g, only then 3 and 4 (§7.9's restored)
rebind   ur keychain recovery-rotate: re-wrap each group's current generation to the new binding at its own b8,
         delete the old binding's wraps only once every new one exists, request a REQUEST rotation, or REMOVE
         for a compromise, which also starts a path epoch at once
```

**Drop** (a holder leaving: §10.5's table): a shrink (revocation, park, Suspend, grant end, Delegation end or key drop, compromise retirement) closes the gate at its entry; an expiry closes it at T_e with no entry; the reconciler hints pending; the engine's next run removes the leaf (if any) and rotates with cause REMOVE; a Delegation's key drop excludes the Delegation's wrap and every parked agent; an unsuspended agent returns by a late ReaderWrap of its own. A ReaderKey lapse or replacement, a move between leaf and wrap, a covered agent's reap and a newer forwarding Delegation drop nothing and rotate nothing (§10.6's never list).

**Re-form** (KEYS-M2-25; plan-KEYS-reform-ladder's rules 1-9): owner marker (6.2.2), form naming previous_group_id and the newest generation held, epoch/0 with no pin, the ladder route in ascending batches of 64, then the group takes commits from epoch 1 with its pin floor at gen/<form.generation>'s auth; readers re-add by KF2 and late wraps; members check the form's signer by §10.6's rule, each C_k against their cache, and judge each GenRotate's signature only where their retained log reaches.

#### 6.2.5 Key access (KEYS-M2-22)

```text
CurrentRepoKey(repo)  the newest generation held and judged: EvsRepoKey{RK_g, C_g, cause, auth, time};
                      ErrGkmUnavailable with none; a stale newest is still answered (reads never wait on a
                      rotation), and §11.7 reads its cause for the checkpoint rule
RepoKey(repo, g)      from the keychain, or the ladder walked down from the newest held through the Signed
                      GenRotates (GET gen?since= for any missing; each verified at its pin where my log
                      reaches, by C_g chain always); a key that is not there is refused, never defaulted
EnsureWritable(repo)  1 require writer at S (ErrGkmNotWriter); 2 Run(c) the pending engine for the changes
                      this device may commit (as a leaf: removes and adds; as a wrapped writer: nothing but
                      first wraps); 3 if ¬covers(g*, n, now) or SCHEDULE due: Rotate (6.2.4), a wrapped
                      writer or a dirty tree by ReaderWraps (R5); 4 refuse (ErrGkmWait) while the newest
                      generation still does not cover at S, even with evs's gate off (the writers' own rule,
                      §8.12), and while a non-holder leaf stands in a tree that wrapped it (R3's poisoned
                      case); 5 return CurrentRepoKey; the witness stop never holds 2 or 3 (owner decision 129)
DropKey(repo)         §10.5's depositor rule: the newest GenRotate gkm serves (GET repos/<id>/drop-key?since=),
                      verified; covers(g, n, now) at my state; now < drop_not_after_ms ≤ time_ms +
                      DropKeyLifetime + 10 min; g not below my pin, which then rises; else ErrGkmWait, and a
                      writer rotates on the renewal hint (plan-KEYS-drop-key-lifetime)
RotateRepo(repo)      ur keys rotate: Rotate with cause REQUEST (never REMOVE unless one is due)
ForgetRepo(repo)      §11.12's shred: drop RK_g, GenRotates, MLS state, pins and pending records
```

#### 6.2.6 Group sync, pins and HeadCheck (KEYS-M2-23)

Each device keeps, per repo, `pins{epoch: (group_id, e, epoch_authenticator), gen: (group_id, g, C_g)}` in the keychain, advanced only forward: a commit adopted, a Welcome completed, a generation claimed, opened or adopted. A lower or conflicting value from any source (a push's sealed epoch pin, a head's generation pin, a GenRotate, a HeadCheck peer) is `head_alarm` (fork) with both values; the device stops sealing in that repo until the chain extends its pin. `GroupHead` and `GenHead` for §6's HeadCheck are these pins, GroupHeads only for groups both peers are leaves of, GenHeads for repos both read, 16 of each a round, rotating by group id. §6.4's rules apply: same epoch, same epoch_authenticator else FORK; same g, same C_g else FORK; the lower side reads `gen?since=` or `epochs?after=` up to the higher, checking the chain, and a chain that does not extend its pin is a FORK. After a re-form, a GenHead's group_id differs: the lower side resolves the repo's newest GroupForm (plan-KEYS-reform-ladder rule 8) and compares (g, C_g) along the form chain. Self-updates: a leaf that committed no path for `SelfUpdateInterval` (`SelfUpdateIntervalLarge` above `LargeGroupLeafCount` leaves) commits a path-only commit under R1-R4, read_only leaves included (D-KEYS-26), and defers it under R3 while its tree holds a dropped leaf. Acks: daily, the newest adopted epoch, per group.
### 6.3 Invariants and why they hold

```text
RemovedReadsNothingNew  for every generation g and party s neither among gen/<g>'s holders nor admitted after
                        its claim (a joiner takes the history down the ladder), s opens nothing at or above g,
                        however much of the store s fetches
                        why: s reaches RK_g only by a GenWrap in an epoch whose tree holds s (R3, R4 keep
                        every epoch wrapping g within g's holders), a leaf_wrap under an epoch whose tree
                        holds s (R5), a STAGED delivery (gen/<g>'s holders) or a LATE one (R6: at a state
                        at or past g's pin, where s is a holder only if it was at g's pin, since holders
                        shrink along the chain by R2); the ladder opens downward only
NoContentToDropped      no content sealed at state n opens to a party dropped at n
                        why: R7 seals only to a generation covering shrunk(n) and expiry(now), whose holder
                        set excludes the dropped party, and RemovedReadsNothingNew keeps it there
RosterWithinHolders     every epoch's tree lies within the holders at its commit's pin, but a generation-0
                        self-join's; why: R3 at the committer, backed by every member's refusal
NoContentPastRefusal    what a member's refusal buys, when a hostile leaf commits what R3 forbids: nothing a
                        device seals after it refused that commit opens to a party dropped at the seal's
                        state
                        why: the refusing device holds the generation the commit's GenWrap carried as
                        poisoned and never seals to it again (R3, §10.9); it is a leaf of the commit's tree,
                        so the newest generation it can open is that one or a later one, and a later one was
                        claimed at a state at or past the first's pin, where the dropped party is no holder
                        (R2), staged to holders alone (R6) and wrapped under no tree that holds the party
                        (R5); R7's coverage does the rest. The three invariants above do not survive such a
                        commit, which leaks the moment it stands (6.2.3)
GenerationsFromWriters  every gen/<g> is claimed by a writer of the repo that holds the key at its pin
                        why: §10.6's claim checks (scope, signer) resolved through the owner marker (6.2.2),
                        so no other repo's scope reaches the group
WelcomesReachable       every Welcome has a pointer its recipient can read; why: one pointer key per (device,
                        group, epoch), created If-None-Match, never shared by two Welcomes
ChainsMonotone          auth pins never fall along the epoch chain or the generation chain; why: R2 at gkm
                        (the epoch PUT and claim checks) and at every member
Convergence             every member at epoch n holds the same tree and epoch_authenticator, and every holder
                        of generation g the same RK_g; why: one If-None-Match object per index, R8's adopt
                        rule, MLS's confirmation tag and C_g; the model keeps the store as the one copy, so
                        this is R8's action structure rather than a checked formula
HoldersReach (liveness) once the log and the rotations stop, every holder of the newest generation holds
                        it; why: a leaf through its epoch's GenWrap or a leaf_wrap, an agent through its
                        staged delivery, a holder whose key lapsed or who joined after the claim through a
                        LATE delivery by any holder that is not read_only (fair), a member device not yet
                        in a data repo's tree through its Add (fair at a writer leaf)
```

**The model.** `sidecartest/model/details/Gkm.tla` keeps one repo A's store as the shared state: the epoch chain (committer, tree, carried generation, pin, time, kind), the generation chain (rotator, holders, pin, time, staged recipients, leaf_wrap epoch), LATE deliveries, Welcomes with their pointer keys, each member device's one-time KeyPackage count, the content sealed (generation, state) and repo B's Welcomes. Each sidecar keeps its tip, the epoch it adopted and the newest it ever reached (I-16). The log is a sequence of admissions, a recovery admission, revocations and an agent's grant expiry; its position is the clock, and an expiry is seen by clock while a revocation is seen by tip, which is how a device with a stale state but a current clock behaves. What a party can open, `Reach`, is derived from the store alone: every GenWrap of an epoch whose tree holds its leaf, every leaf_wrap under such an epoch, every delivery to it, its recovery wraps, and the ladder below; so a removed device that fetches the whole store, or colludes with the server, is the adversary. Five sidecars: a the creator and a writer leaf, b a writer leaf, c a read_only leaf, d an agent that rotates and delivers but never commits, e the device a member's recovery code admits, which the squat twin casts as a reader of A and admin of B. Actions: an entry, a device's advance, a member's processing of the next epoch, a leaf's commit (Add, Remove, path-only, a stale Remove) carrying every pending Remove it may, a Welcome join, an Add in B, a rotation, a LATE delivery, a resync by external commit, the recovered device's self-join, a lost state, a content seal under the gate, and under the squat twin the form and claim. It leaves out ReaderKey lapses and replacements (a delivery to a holder is a delivery to a key it holds), Delegations and their covered agents (an agent holds its own wrap), the leaf rank of the config group, GroupInfo availability, the 412 loser's adoption (two rotations are two claims), gkm's rate limits and the write budget, and the server's forks (HeadCheck's domain, §6). `Losers` names the devices that may lose their state, `StaleTargets` the leaves a writer may remove as stale, `WithB` whether repo B adds devices and `Hostile` the leaves that may inject a commit, so a configuration's bounds are its constants.

The poison rule (QD-644). Where `Hostile` names a leaf, `Inject` lets it commit, once in a behavior, what no honest leaf does: at the newest epoch, a commit whose tree holds a party dropped at the commit's own header, carrying the newest generation, at any pin gkm's epoch PUT check takes. gkm cannot refuse it, since the commit is a PrivateMessage and its sender holds a writer's token and the generation. Each device keeps `poisoned`, the generations it refused a commit for: a member that processes the injected commit never adopts its epoch and adds the generation its GenWrap carried, and `Seal` takes no generation its sealer holds as poisoned. A seal records whether its sealer had refused, and `NoContentPastRefusal` is over those seals. The store invariants are not checked in these configurations: they fall at the injection itself, which is 6.2.3's "a bad commit leaks the moment it stands". Nor does the invariant speak for a writer that has not processed the commit: a wrapped writer, which reads no commit, seals to the carried generation until the REMOVE rotation's delivery reaches it, and so does a leaf whose seal races the injection. That window is the leak's own, and a refusal cannot close it; the refusing member's rotation at once is what ends it. The model leaves the group's repair to the actions it has: the recovered device's generation-0 self-join over the bad epoch, its Remove, and the resyncs that follow. `Twin` selects a rule to break; `Story` fixes each twin's actions so TLC reaches its violation directly; the design runs with no story. `run-gkm.sh <track>` runs every configuration (`Gkm`, `Gkm-Epochs`, `Gkm-Live`, `Gkm-Wide`, `Gkm-Deep`, `Gkm-Poison`, `Gkm-PoisonWide`, the twins and the reach configuration) through `.stack/tools/tlc` and prints a verdict line per run; it stops a run whose state directory passes 8 GB on the shared disk and deletes every run's state directory when it ends, so a run is bounded on disk as it is in states.

Runs, TLC at the owner's jar (master d8fb231), all run again on 2026-11-10 on the model with the poison rule, on a machine carrying four build lanes: `Gkm`, `Gkm-Epochs`, `Gkm-Live` and `Gkm-Poison` breadth-first over every reachable state at their bounds, `Gkm-Wide`, `Gkm-Deep` and `Gkm-PoisonWide` by TLC's random simulation, a fixed number of traces of a fixed depth from a fixed seed, since their complete graphs pass the disk a shared build machine can give a run (the breadth-first search at MaxLog 2, MaxEpochs 4 and MaxGens 3 held 62 GB of state after 3.5 h without finishing on 2026-11-09 and was stopped); a simulation shows only that the behaviors it drew kept every invariant:

```text
configuration                 Twin                    bounds (MaxSeals 1; ReadOnly {c}; Agents {d}; Recovered e; Squatter e)
                                                      result                                   distinct states  depth  time
Gkm                           none                    MaxLog 1, MaxEpochs 3, MaxGens 2; readers a, c, d, leaves a, c, writers a, d, e;
                                                      no lost state, no stale Remove; breadth-first
                                                      pass, every invariant                      419,200        17     16 s
Gkm-Epochs                    none                    the same at MaxEpochs 4
                                                      pass, every invariant                      4,864,888      20     5 min 10 s
Gkm-Live                      none                    Gkm's bounds under LiveSpec's fairness, the property Live
                                                      pass, Live and every invariant             419,200        17     1 min 15 s
Gkm-Wide                      none                    MaxLog 3, MaxEpochs 4, MaxGens 3; readers a, b, c, d, leaves a, b, c, writers
                                                      a, b, d, e; b may lose its state, c may be removed as stale; by random
                                                      simulation, 200,000 traces of up to 12 steps from seed 1
                                                      pass, every invariant on those traces      36,538,695 generated   5 min 7 s
Gkm-Deep                      none                    MaxLog 2, MaxEpochs 5, MaxGens 3, the same devices; 100,000 traces of up to
                                                      16 steps from seed 2
                                                      pass, every invariant on those traces      25,299,525 generated   4 min 38 s
Gkm-Poison                    none                    MaxLog 1, MaxEpochs 3, MaxGens 2; readers a, b, c, d, leaves a, b, c, writers
                                                      a, d, e; Hostile {c}; breadth-first; NoContentPastRefusal with
                                                      GenerationsFromWriters, WelcomesReachable and ChainsMonotone
                                                      pass, those four                           5,547,336      21     3 min 40 s
Gkm-PoisonWide                none                    MaxLog 3, MaxEpochs 5, MaxGens 4, MaxSeals 2; Gkm-Wide's devices; Hostile
                                                      {b, c}; the same four invariants; by random simulation, 200,000 traces of
                                                      up to 16 steps from seed 3
                                                      pass, those four on those traces           49,251,637 generated   15 min 20 s
GkmTwin-PointerByRef          PointerByRef            StoryPointer, WithB   WelcomesReachable violated, 6-state trace      6     6
GkmTwin-FormsUnchecked        FormsUnchecked          StorySquat, e a reader of A, not a writer
                                                                            GenerationsFromWriters violated, 5 states    5     5
GkmTwin-GenWrapIgnoresRoster  GenWrapIgnoresRoster    StoryGenWrap          RemovedReadsNothingNew violated, 6 states    6     6
GkmTwin-SelfJoinCarriesGenWrap SelfJoinCarriesGenWrap StorySelfJoin         RemovedReadsNothingNew violated, 8 states    8     8
GkmTwin-LateBelowClaimPin     LateBelowClaimPin       StoryLate             RemovedReadsNothingNew violated, 5 states    5     5
GkmTwin-ClaimBelowParent      ClaimBelowParent        StoryClaim            RemovedReadsNothingNew violated, 5 states    5     5
GkmTwin-LeafWrapDirtyTree     LeafWrapDirtyTree       StoryLeafWrap         RemovedReadsNothingNew violated, 4 states    4     4
GkmTwin-NoGate                NoGate                  StoryGate             NoContentToDropped violated, 3 states        3     3
GkmTwin-MembersSkipRosterCheck MembersSkipRosterCheck StoryPoison, Hostile {c}
                                                                            NoContentPastRefusal violated, 8 states      8     8
GkmReach-SealsPastRefusal     none                    the design at MaxLog 1, MaxEpochs 3, MaxGens 3, readers and leaves a, b, c,
                                                      Hostile {c}, with "no seal is made after a refusal" denied
                                                                            NeverSealedPastRefusal violated, a 7-state trace
```

The poison runs. `GkmTwin-MembersSkipRosterCheck`'s trace is the leak a refusal contains: b is revoked; the agent rotates to generation 2, which excludes b; the hostile leaf c commits a path with b's leaf standing, carrying generation 2, so b opens it; a processes that commit and, under the twin, adopts it and seals to generation 2, which b reads. In the design a refuses, and `Gkm-Poison` holds over every behavior at its bounds that nothing a refuser then seals opens to a dropped party. It is bounded at two generations: with a third its complete graph passed 16 million states with the queue still growing and was stopped inside the disk rule. Two generations hold both cases: a commit that carries generation 1, refused, after which the refuser rotates and seals to generation 2; and a commit that carries the REMOVE generation 2, refused, after which the refuser seals nothing, there being no generation left to rotate to. A rotation past a leaked REMOVE generation is in `Gkm-PoisonWide`'s traces, with a second hostile leaf, a lost state and a stale Remove, and in the reach configuration, which shows the design does get past a refusal: its trace ends in a seal by the refuser to the generation its own rotation made. The simulation is not idle on the point: with the reach invariant in place of the four, the same seed meets a seal after a refusal within its first 30,000 states. The twelve earlier twins, the eight above and the four the tasks added (`AddWithoutRemove`, `StagedToNonHolder`, `AdoptNonCoveringWinner`, `FormWithoutMarker`), were run again on this model and each ends on its invariant with the trace it had.

Each twin run took about a second, and its distinct-state count is its trace, since the story leaves TLC one path; a depth counts TLC's initial state. The twins run at MaxLog 3, MaxEpochs 5 and MaxGens 3 with every device, so their stories are reachable at the design's wider bounds. The breadth-first runs explore every behavior their constants allow, and `Gkm-Epochs`, one commit deeper, took ten times `Gkm`'s states; a run with one more entry, device or generation passes the shared disk's bound, so those bounds run by simulation, whose seeds and trace counts are fixed in `run-gkm.sh` and repeat. Every run deleted its state directory on exit and stayed under 2 GB on disk. The design's five earlier runs explore the graphs they did: `Hostile` is empty there, the new variable never moves, and the three breadth-first counts are the ones first recorded; the simulations' counts differ a little, since a new action changes the order the same seed draws in. The three failures of §10 as written (6.1) appear in `GkmTwin-PointerByRef` (the second Welcome of a last-resort KeyPackage has no pointer), `GkmTwin-FormsUnchecked` (a reader of A claims A's next generation under B's scope) and `GkmTwin-GenWrapIgnoresRoster` (the read_only leaf's self-update hands the removed leaf the REMOVE generation), and are gone in the design: the design runs hold every invariant at the same and larger bounds, with the same log alphabet, devices at every combination of tips, concurrent commits and rotations from every leaf and the agent, deliveries in every order, lost state, resyncs and the recovery self-join. The five design-rule twins show what each fence is for: without R2 at the claim (`ClaimBelowParent`), R6's pin (`LateBelowClaimPin`), R5 (`LeafWrapDirtyTree`), R4's exception (`SelfJoinCarriesGenWrap`) or R7 (`NoGate`), a removed leaf reads what the design keeps from it.

### 6.4 Cost

Against D-KEYS-14's table, which §22.8's `groups` benchmark (KEYS-M2-31) measures; RFC 9420's structures on suite 0x0010, X-Wing public key 1,216 B and ciphertext 1,120 B, Ed25519 32 B and 64 B, credential 207 B:

```text
tree          leaf 1.54-1.57 KB (X-Wing encryption key 1,216, signature key 32, credential 207, capabilities
              and extensions ~50, signature 64); parent 1.25 KB plus 4 B an unmerged leaf; so 10 leaves
              16-27 KB, 100 leaves 158-282 KB, 1,000 leaves 1.58-2.83 MB (parents blank .. full), which is
              D-KEYS-14's 2.83 MB and stands: nothing here adds a node
commit        a path commit updates log2(leaves) levels, each a new X-Wing key and one ciphertext (1,120 B
              plus a 48 B sealed path secret) per node of its copath resolution: every parent full, ~2.4 KB
              a level, 26 KB at 1,000 leaves; every parent blank, the top level's resolution is ~500 leaves,
              1.18 MB; an Add-only commit 0.2 KB plus 2.85 KB a joiner; a PrivateMessage adds ~100 B of
              framing; the GkmCommitHeader 50 B; GenWrap 72 B; the inline GroupInfo at ≤ 16 leaves under
              50 KB
Welcome       0.4 KB plus 1.2 KB a joiner (one X-Wing ciphertext each), no tree: the joiner takes the tree
              from the sealed GroupInfo (0.7 MB at 1,000 leaves, one GET)
pointer       GkmWelcomePointer grows by the 32 B ref; one object per (recipient, group, epoch) as before
owner marker  one 40 B object per group, written once; one GET per group per gkm process, then cached
rotation      GenRotate ~0.5 KB (1.7 KB with a drop key); ReaderWrap ~1.37 KB staged, ~1.42 KB late;
              RecoveryWrap 1.17 KB; a leaf rotator with a clean tree stages one 72 B leaf_wrap for every leaf
              and a wrap per agent, Delegation and recovery binding; a wrapped rotator, or a leaf whose tree
              holds a dropped leaf, a ReaderWrap per leaf: 1,000 leaves cost ~1.37 MB of staged objects,
              ~45 batched requests (QD-066) and ~9 KiB a drive per object (§11.13); the config and directory
              groups at a 5,000-admission Team: ~6,000 objects, ~7.5 MB, as §10.15 sizes it
memory        measured, not estimated (question keys-m2-23-large-group-memory, QD-641): KEYS-M2-31's harness
              (sidecartest/bench_groups.go, darwin/arm64, a Go memory limit of the step's start plus 32 MiB)
              samples the heap's rise over one step of a 1,000-leaf group: a Welcome join 27.5 MB, a path
              commit with every parent blank 45.9 to 50.1 MB, a resync by external commit 62.6 MB; at 100
              leaves 3.7, 7.8 and 7.5 MB, at 10 leaves 0.4, 0.8 and 1.2 MB. Every size above holds at each
              count; the heap is three to six times this row's first estimate of "under ~10 MB", which is
              withdrawn. The figures count garbage not yet freed and a 64-bit leg's pointers, so the ios32
              cell will read lower, and its own run of the harness is the number §22.8's groups row is held
              to. No profile was taken; what is known is what each step does: the engine holds the tree
              whole in RAM (2.83 MB encoded; KEYS-M2-06 logged 3.6 MB allocated to decode a 2.6 MB tree), a
              path commit clones the tree and the key schedule before it stages (mls_group.go) and holds its
              whole output (1.18 MB in the blank-parent case), and a resync decodes and validates the
              GroupInfo's tree twice (GroupInfoRoster, then JoinExternal).
              The owner's direction (BRIEF.md, 2026-11-10): the SDK keeps bulk state on storage and RAM as a
              working set. For the engine, in the review phase, in KEYS-M2-06's, -08's and -09's files: the
              ratchet tree stays on disk in the sections mls_state.go already writes a node at a time, and
              is hashed, validated and encoded by streaming them; a path is sealed and written a node at a
              time, never held whole; a resync decodes its tree once; and a commit copies its own path on
              write, in place of cloning the tree. No format or flow changes. Until then the harness
              reports the peaks and fails nothing on them; if the ios32 cell still reads over §18.4's
              budget after that work, bounding the roles of a 32 MiB leg is raised as its own question.
              Unchanged: the pending engine's record and pins are under 1 KB a repo, and a 1,000-generation
              ladder is ~0.5 MB of Signed GenRotates beside 32 KB of keys, both on disk
store         per §10.6's table, unchanged for commits (4 GETs and a PUT), rotations (1 GET, W PUTs, 1
requests      claim), Adds (claim, delete, Welcome, pointer, group-info) and late wraps; plus: creation and
              re-form +1 PUT (the marker); group resolution +1 GET per group per process (was a form read
              per 5 s); H1 adds at most one hint a minute per group with a dropped holder, on Redis only;
              H2 one GET a minute per waiting leaf; a self-update after a last-resort join is one commit
              more per such join
time          a 1,000-leaf path commit: ~10 X-Wing encapsulations and ~10 decapsulations a member in the
              full-parent case (under 1 ms each on a 2020 phone core), ~500 at the top level in the blank
              case (~0.5 s, which the js/wasm leg yields across, KEYS-M4-01); a 1,000-leaf tree hash ~1 ms
```

### 6.5 Failure modes and recovery

```text
a commit a member refuses   the object stands; the member alarms (refused, naming committer and epoch), adopts
                            nothing, seals nothing to the generation it carried; honest committers never make
                            one (R3 at the committer), so this is a bug or a compromised leaf; repair: a writer
                            leaf's Remove of the committer, a REMOVE rotation (6.2.4), and the refusing
                            members process on from the repaired chain, or an admin re-forms the group
                            (KEYS-M2-25); content sealed to the poisoned generation re-checkpoints at its
                            next write (§11.7)
a dropped leaf stands       (a wrapped writer rotated; every leaf offline or read_only) reads continue, the
                            gate is open, read_only self-updates and every resync wait (R3); H1 hints the
                            writer leaves each minute until one commits the Remove; a read_only leaf whose
                            self-update waits past stale_leaf_days is removed as stale and returns by resync,
                            which waits on the same Remove; no leak, since no epoch wraps the new generation
                            into that tree
a lost Welcome              the uploader crashed between epoch/<n> and welcome/<n>: a writer leaf sees no
                            Welcome after WelcomeTimeout, removes and re-adds the joiner; a slow uploader's
                            late Welcome lands at its own pointer key and the joiner takes the newer one
a lost claim                staged objects with no gen/<g>: GC after 24 h; the rotator resumes from its draft
                            with the same bytes, or finds another's claim and judges it
a 412 that does not cover   the loser fetches its delivery of the winner (a late ask if it has none), then
                            rotates again at g+2 for what the winner left uncovered
a rotator ahead of gkm      403 at the claim (auth gkm's state has not reached): retry when gkm's state
                            arrives (§8.9's 5 s), a time refusal when the clock moves
a generation no holder can  every delivery to a lapsed key: the holder publishes a new ReaderKey and asks; any
open                        holder but a read_only one delivers (15 min, then 64 others); a leaf also takes
                            the next GenWrap; nothing is lost, since the ladder opens downward from any later
                            generation it gets
gkm down (KF7)              reads and deposits from the keychain; writes while covered; joins, rotations,
                            deliveries wait on the hint intake's resync
a device far behind         KF5's resync from the newest GroupInfo under the generation it names, which a late
                            delivery gives; above 16 leaves, one leaf online writes the GroupInfo on the ?want=
                            hint
a device with lost state    resync (its leaf stands) or, with the keychain gone, the member's recovery code
                            (6.2.4's Recovery), or an admin's re-add after revocation
a group-id collision        409 at the owner marker: the creator draws another id; a re-form naming a taken id
                            is refused and the admin re-forms with a fresh one
a squatting form            refused at the marker (409); nothing written
a re-formed group's first   refused until gen/<form.generation> exists (plan-KEYS-reform-ladder rule 5); the
commit                      re-former uploads the ladder first, then commits
site loss                   D-KEYS-13: a repo admin's device re-forms from its keychain (RK_g and the Signed
                            GenRotates), the marker and form first; readers re-add by KF2 and late wraps
a fork at any pin           head_alarm (fork) with both values; sealing stops in that repo until the chain
                            extends the pin; §6.4's HeadCheck relays it
```
### 6.6 The test plan

Unit tests (sidecar root, each a top-level `func TestXxx`, on `FakeMls` then the real subset, fake clocks and barriers only, `testHookSecret` at every key and `testHookBarrier` at every claim and epoch PUT):

```text
TestACommitCarriesEveryPendingRemove             a writer leaf at a state past two revocations commits one Remove of
                                                 both with its Add; a member refuses the same commit made without
                                                 them (R3) and alarms refused naming the committer
TestAReadOnlyLeafWaitsWhileADroppedLeafStands    after a wrapped rotation the read_only leaf's due self-update
                                                 waits, asks H2, and commits once a writer leaf's Remove lands; the
                                                 twin's commit, injected, is refused by every member
TestAResyncWaitsWhileADroppedLeafStands          KF5's external commit waits under R3 and lands after the Remove
TestNoEpochWrapsAGenerationToANonHolder          over generated runs (revocations, rotations by leaves and the agent,
                                                 commits from every leaf, resyncs, the self-join), every stored
                                                 epoch's tree lies within the holders of the generation its GenWrap
                                                 carries, and Reach of each removed device, computed as the model
                                                 does from the fake store, stays below the first generation after
                                                 its drop
TestARotationsClaimNeverFallsBelowItsParent      a rotator at a stale tip refuses to claim (ErrGkmAuthAhead) and
                                                 gkm refuses a claim whose auth is below gen/<g>'s
TestALateDeliveryIsSignedAtOrPastTheClaimsPin    a holder behind the claim does not deliver; one at the pin does; a
                                                 LATE delivery below the pin, injected, is refused by gkm and
                                                 judged invalid by members
TestALeafWrapNeedsACleanTree                     a leaf whose tree holds a dropped leaf rotates by ReaderWraps to
                                                 every leaf; with a clean tree one leaf_wrap; the removed leaf opens
                                                 neither
TestARecoverySelfJoinCarriesNoGenWrapOverLostLeaves
                                                 generation 0 while the lost devices' leaves stand, generation g*
                                                 with a clean tree; the recovered device's next commit removes them
                                                 and the rotation after is the first new generation (FS-20)
TestAWelcomePointerIsKeyedByGroupAndEpoch        a device whose last-resort KeyPackage served two Adds in two groups
                                                 holds two pointers and joins both; two Adds of one device in one
                                                 group (the 10-minute re-add) leave two pointers and it joins the
                                                 newer; a pointer at or below its reached epoch is skipped
TestALastResortJoinSelfUpdatesAtOnce             the joiner's first commit after a last-resort join is a path-only
                                                 commit, and its next upkeep pass replaces the last-resort
                                                 KeyPackage
TestAGroupBelongsToOneRepo                       a form for B naming A's group answers 409 at the marker and writes
                                                 nothing; a B-scoped token reaches none of A's routes; equal bytes
                                                 resume a crashed creation; the shred deletes the marker and a
                                                 re-seed's form writes it again
TestAReformsFirstCommitFloorsAtTheFormsGeneration
                                                 epoch 1 of a re-formed group is refused below gen/<form.generation>'s
                                                 auth and before the ladder reaches that generation
TestEnsureWritableCommitsThenRotatesThenRefuses  the four steps in order on a fake clock: pending changes committed,
                                                 a REMOVE rotation when uncovered, SCHEDULE at 30 days, ErrGkmWait
                                                 while uncovered at my state with evs's gate off
TestKeyAccessWalksTheLadderFromAnyHeldGeneration RepoKey(g) from a newest held generation through cached and fetched
                                                 GenRotates; a wrong C_g, GenLink, AAD width or cause refused; gen/1
                                                 with cause REMOVE refused
TestPinsNeverFall                                a lower or conflicting epoch or generation pin from a push, a head,
                                                 a GenRotate or a HeadCheck peer raises head_alarm (fork) and stops
                                                 sealing; the chain extending the pin resumes it
TestDropKeyFollowsTheDepositorRule               FS-23's M2 half as a unit: an older unexpired GenRotate after a
                                                 removal refused with evs's gate off; a lapsed drop key waits
TestTheLadderAadWidthsArePinned                  testdata/gkm/ladder.json byte-equal on every leg (exists; gains the
                                                 gen/1 cause row)
```

Schedule rows (KEYS-M2-27 to -29, KEYS-M4-01), each with its success twin and `ApplyThenDrop` where a write is involved: FS-15 gains "a wrapped rotation while a leaf stands, then the read_only leaf's self-update waits under R3, the writer leaf's Remove releases it, and the removed leaf opens nothing of g+1", "a resync waiting on the same Remove", "a claim at a stale tip refused" and "two Adds of one device through its last-resort KeyPackage in two groups, both joined"; FS-20 gains "the self-join's generation 0 only while the lost leaves stand" and "a kill between the owner marker and the form, then the form and epoch/0, resumed with equal bytes"; FS-24 gains "H1's pending hint while a dropped holder precedes the newest epoch's pin, stopping at the first commit past it" and "H2's want from a waiting leaf"; FS-103 gains "a LATE delivery whose signer's state trails the claim refused, and one at the pin accepted"; FS-104 gains the twin's injected commit "refused by every member and the oracle, the carried generation poisoned"; FS-6 and FS-41 gain the marker (deleted at a shred, written by a re-seed's form, refused for another repo); FS-97's leaf legs gain "a stale Remove of a page Worker whose tree holds a dropped leaf carries that Remove too". §22.7's committers block gains "a squatting form refused" and "a last-resort join's immediate self-update".

Model twins the tasks add to `Gkm.tla` (new twin values and stories; the file's own tests are the configurations in `run-gkm.sh`): `MembersSkipRosterCheck`, which this list gave KEYS-M2-19, is in the model as the owner's answer has it (question keys-m2-19-members-skip-roster-twin, option 1; QD-644), added by this section's own track: a hostile leaf's `Inject`, each device's `poisoned` set, `Seal`'s refusal of a poisoned generation and the invariant `NoContentPastRefusal`, which the twin breaks by having members adopt the injected commit and seal on to the generation it carried (6.3 records the runs). It could not be the twin first asked for, a break of `RemovedReadsNothingNew`: that invariant falls at the injection itself, whatever members do. KEYS-M2-19's Go tests of the member side stand (`TestAMemberNeverAdoptsACommitThatLeavesADroppedLeaf`, `TestAReadOnlyLeafWaitsWhileADroppedLeafStands`); KEYS-M2-20 adds `StagedToNonHolder` (a rotation stages a delivery to a party outside its holder set, `RemovedReadsNothingNew`) and `AdoptNonCoveringWinner` (the 412 loser adopts and seals to a winner that does not cover its shrink, `NoContentToDropped`); KEYS-M2-21 adds `AddWithoutRemove` (an Add commit that leaves a dropped leaf, `RosterWithinHolders`); KEYS-M2-24 adds `RecoverBeforeAnchor` as a story under a lying-store flag if one is added, else a unit test; KEYS-M2-25 adds `FormWithoutMarker` (`GenerationsFromWriters`). Each twin names the invariant it breaks, as the configurations here do.

mlsinterop vectors (KEYS-M2-11's artifact, §22.10's ladder row): `ladder_test.go` gains the gen/1 cause byte (REQUEST, 0x02) in GenLink's AAD and a GenWrap of a generation-0 self-join's epoch (none: the row records that epoch's GenWrap is empty and its GroupInfo seals under `group_info_generation`); `testdata/gkm/wrap_paths.json` gains `gkm/welcome/<sidecar_id>/<group_id>/<n>` and `gkm/<group_id>/owner`; the stacks row's lifecycle gains a join through a last-resort KeyPackage (tmc/mls sends `last_resort` 0x000A) followed by the joiner's path commit, so both stacks agree on the extension's number and placement; and a GroupInfo with `ratchet_tree` from a tree holding a last-resort leaf.

### 6.7 Implementation notes, task by task

Order: the formats first (KEYS-M2-19's branch carries the proto and path changes, since every later task reads them), then member checks (-19), rotation and deliveries (-20), the engine and flows (-21), key access (-22), sync and pins (-23), recovery (-24), re-form (-25), the commands (-26), then the schedules (-27 to -29), sizes (-31) and the page Worker (M4-01).

**Landed code that must change** (sidecar root unless said):

```text
protocol/gkm.proto             GkmWelcomePointer.key_package_ref = 3; new GkmGroupOwner{repo_id = 1; network_id = 2};
                               the GkmEpochObject comment at epoch 0 of a re-form: "no auth; epoch 1's floor is
                               gen/<form.generation>'s"; testdata/gkm/metadata_rows.yml rows for both (gkm-1, gkm-5)
gkm_paths.go                   GkmWelcomePointerPath(sidecarId, groupId, epoch), GkmGroupOwnerPath(groupId); the
                               wrap_paths.json vectors gain both
gkmservice/welcomes.go         pointers at the new key; the collision count and alarm go; the Welcomes listing reads
                               the ref from the pointer
gkmservice/groups.go           the owner marker as the first write of a creation and a re-form, 409 on other bytes;
                               the LIST goes; GET /gkm/groups/<id> and every group route resolve through the marker
                               (a new gkmGroupOwners cache, immutable entries); the re-form's epoch 0 unchanged
gkmservice/epochs.go           the epoch PUT check's floor for epoch 1 of a re-formed group: gen/<form.generation>'s
                               auth, read through generations.go's accessor; the fail-closed refusal of a pinless
                               previous epoch narrows to that case
gkmservice/reconciler.go       H1: pending hints while a holder dropped since the newest epoch's pin and time, from
                               the same state watch; H2's want is groupinfo.go's existing hint
gkmservice/shred.go            deletes gkm/<group_id>/owner with the group's objects
gkmservice/objects.go          the owner family in the key inventory
sidecartest/fake_blobs.go      path-prefix rule (EVSB's file: raise with the question, not an edit; until then
                               KEYS-M2-13's filter stays)
sidecartest/fake_gkm.go        FakeGkm gains the roster rule's effect for FakeMls trees: a client's rotation uses a
                               leaf_wrap only on a clean tree, and EnsureWritable's step 2 runs the pending engine
                               (KEYS-M2-21's seam) before it rotates
gkm_upkeep.go                  after a last-resort join: replace the last-resort KeyPackage at the next pass
                               (KEYS-M2-23 reports the join to upkeep through GkmUpkeepRole)
mls_extension.go, gkm_keys.go  unchanged: 0x000A and the widths stand as built
```

**KEYS-M2-19 (member checks).** Build first, with the format changes above on its branch. `CheckCommit(view, group, staged, header)` runs §10.9's committer and check rows at `header.auth` (`GkmAuthView.At`, waiting with `ErrGkmAuthAhead`, fork on `ErrGkmAuthOffChain`), then R3: `staged.Added()`, `Removed()` and the new roster against `KeyHolders(view.At(header.auth), repo, header.time)`, the generation-0 external-commit exception for a recovery-admitted uploader only; then R4: `header.generation` at or past the previous epoch's and its GenWrap opening to `gen/<g>`'s `C_g`. Stale Removes by the owner's rule (`UrMlsCredential.not_after - 90 d + stale_leaf_days <= my clock + 60 s`, read from the prior epoch's tree), in one function `gkmStaleRemoveValid`. `CheckRotation` is §10.9's rotation checks with R2 (auth and time at or past the parent's); `CheckDelivery` the delivery checks with R6, judged at the delivery's own state. The poison verdict: a type `GkmVerdict{Refused bool; Poisoned uint64 (generation); Reason}` the engine and sync read. Tests: one refusal and one success per row, the R3 cases above, S3's forged admission, KeyPackage and ReaderKey; the oracle (KEYS-M2-29) stays separate code.

**KEYS-M2-20 (Rotate and late deliveries).** 6.2.4's Rotate as one code path for every cause and rotator, `persist draft` through the keychain's `gkm/<repo_id>/draft` item, batched staging through `GkmApi.UploadWraps` and `UploadRecoveryWraps`, the claim through `ClaimGeneration` with `testHookBarrier` around it, and the 412 branch with `CheckRotation` and the cover test (`GkmGenerationCovers` against what this rotation rotates for). R5's leaf case from `MlsGroup.Roster()` against H. `drop_public_key` and `drop_not_after_ms` for kinds that take deposits or an inbox (RESOLUTIONS plan-KEYS-drop-key-lifetime and plan-MAIL-group-inbox). Late deliveries as 6.2.4's deliver, with R2's `tip >= gen/<g*>.auth` precondition and the readerkey check; `dwraps` for a Delegation's signer. Tests: KEYS.md's list plus 6.6's rotation rows; a kill before and after each step resuming from the draft.

**KEYS-M2-21 (membership flows).** The pending engine as 6.2.4 (one `gkmGroupManager` per group, single-flight, inputs `AuthAdvanced` and the hint intake's `pending`, `welcome` and `wrap-pending` handlers), with `Pending(S, e)` as a pure function (`gkm_members.go`) the tests and the oracle can call, `may(c)` from §10.9's committers, seats from §8.12 (`gkm_seats.go`, reusing §7.9's leaves rule for the config and directory groups), KF1 as the state machine with its keychain draft and the `activate` call after the deliveries, KF2/KF3 through the engine, KF4 through the engine then `Rotate`, KF6's loser path, the `WelcomeTimeout` re-add, and the owed-Welcome record. `GkmClient.CreateGroup` and `AuthAdvanced` land here; `EnsureWritable`'s step 2 calls `Run(c)`. Tests: §22.5's KF1 to KF4 and KF6 on `FakeMls` then the real subset, the engine's R3 cases, a kill at each KF1 step, a repo never activated before its recovery wraps exist, the two-group last-resort join.

**KEYS-M2-22 (key access).** 6.2.5 as written, over the keychain's `gkm/<repo_id>/gen/<g>` items (RK_g with the Signed GenRotate bytes, plan-KEYS-reform-ladder rule 2), `gkm_ladder.go` walking down through cached or fetched GenRotates with `OpenGkmLadder`, `EnsureWritable`'s four steps, `DropKey` over `GkmApi.DropKeys`, `ForgetRepo`, and the late ask (`GkmLateAsks`, landed in gkm_api.go) driven from a `wraps` fetch that finds nothing for a held key. The checkpoint signal is `EvsRepoKey.Cause()` (landed). Tests: 6.6's key-access rows; FS-23's half; a pin that never falls.

**KEYS-M2-23 (sync, pins, HeadCheck).** 6.2.6: KF5 with R1-R4's preconditions and the R3 wait with H2; self-updates with the wait; `gkm_pins.go` keeping `gkm/<repo_id>/pins` and answering `GroupHead` and `GenHead` to PROTO-M2-02's HeadCheck (its `SealAllowed` and `ReportFork` seams, PROTO-M2-04); the commit-hint handler (fetch `epochs?after=`, Process each); acks through upkeep's `AckGroups`; the last-resort join's immediate self-update and its report to upkeep. Tests: KEYS.md's list plus 6.6's pin and wait rows; replay at 100 and 101 epochs; a fork at one epoch alarming.

**KEYS-M2-24 (recovery).** 6.2.4's Recovery with its states persisted (`gkm/<repo_id>/pending` carries the recovery phase), the generation-0 self-join exactly when the tree holds a non-holder at the device's tip, the ordinary external join otherwise, the next commit's removes through the engine, then `Rotate`; the restored order; the rebind's re-wrap and delete order. Tests: §22.7's recovery rows and 6.6's self-join row; FS-20's and FS-22's cases run in -27 and -28.

**KEYS-M2-25 (re-form and re-seed).** No longer blocked: plan-KEYS-reform-ladder is decided and 6.2.2 settles epoch 0's floor and the marker. Build `gkm_reform.go` (the re-former's form, marker, epoch 0, ladder upload in ascending batches of 64, re-adds and wraps) and `gkmservice/reform.go`'s ladder route (QD-074's checks) and the floor rule. Tests: FS-6's gkm legs, a re-form refused from a non-admin device, a member refusing a mismatched C_g, a re-form naming a taken group id refused at the marker, FS-41's group legs on T3.

**KEYS-M2-26 (`ur keys rotate`, `ur evs rekey`).** Unchanged in scope; `RotateRepo` is `Rotate` with cause REQUEST, REMOVE only if one is due (`GkmRotationRemoveRequired`).

**KEYS-M2-27, -28, -29 (schedules).** As the plan has them, plus 6.6's added rows; -29's `DeliveryOracle` judges from the log and the fake store alone and, for FS-104's new case, computes `Reach` as the model does; FS-15's wrapped-rotation-then-read_only-self-update case is the schedule that shows the leak twin refused on real code.

**KEYS-M2-31 (sizes).** As the plan has it; the table gains the owner marker and the new pointer, and the memory row measures the join, path-commit and resync peaks 6.4 records (a sampled peak on the ios32 surrogate, not allocation totals), reports them, and fails nothing on them until the review phase's storage-backed engine lands (QD-641).

**KEYS-M4-01 (page Worker and stale leaves).** The group view §7.10's stale row needs (`SidecarStaleGroupView`'s real implementation over the engine's `Pending` and the credential `not_after` rule), the yield points, and the read_only leaf's R3 wait: a Worker whose self-update or resync waits must not count as stale for that reason alone (its leaf's credential is what the stale rule reads, so a Worker that cannot commit because a dropped leaf stands is removed only after stale_leaf_days, as any quiet leaf, and returns by resync once the Remove lands). FS-97's leaf legs as 6.6 adds them.

Scope changes: KEYS-M2-25 loses its "blocked on the question" clause; KEYS-M2-19 gains the proto and path changes; KEYS-M2-21 gains the pending engine's R3 and the WelcomeTimeout re-add as named parts; KEYS-M2-23 gains the R3 wait and H2; no held task loses scope.
### 6.8 Proposed DESIGN.md text

For the design-records track, section by section; each replaces the sentence or row named.

**§10.4, the credential block.** Add: "A last-resort KeyPackage carries draft-ietf-mls-extensions' `last_resort` extension, type 0x000A with empty extension_data, in its own extensions, and every leaf lists 0x000A and 0xF553 in its capabilities; a device that joined through it commits a path-only self-update at its first opportunity and replaces it at its next upkeep pass."

**§10.5, the hierarchy block.** After `GroupInfo_e` add the widths: "GenLink's AAD is repo_id || u64be(g) || u8(cause_g), GenWrap's and LeafWrap's group_id || u64be(e) || u64be(g), GroupInfo's group_id || u64be(e); gen/1 carries cause REQUEST." In Rotate's step 3 `leaves` row, after "else a ReaderWrap to each leaf's ReaderKey" add "(a leaf_wrap never uses an epoch whose tree holds a non-holder)".

**§10.6, the object table.** Replace the `gkm/welcome/<sidecar_id>/<ref>` row with `gkm/welcome/<sidecar_id>/<group_id>/<n>`, "with the Welcome; pointer {group_id, n, key_package_ref}; one per Welcome, so a last-resort KeyPackage's Welcomes never share a key; a device holding several for one group takes the highest n above the newest epoch it reached". Add a row `gkm/<group_id>/owner`, "If-None-Match, the first write of a creation or re-form; {repo_id, network_id}, written by gkm from the token; the only binding of a group to its repo, through which every group route resolves; deleted by the shred". In the checks row replace "whose newest GroupForm names the group" with "which gkm/<group_id>/owner names, among the token's scopes, and whose newest GroupForm names the group". In the Welcomes row replace "joiners get a pointer and a welcome hint" with "joiners get a pointer, keyed by group and epoch, and a welcome hint". In the epoch PUT check add: "never below the previous epoch's, or, for epoch 1 of a re-formed group, below gen/<the form's generation>'s auth, since a re-form's epoch 0 carries none". Add to the pending changes row: "and every 60 s while its newest verified state shows a holder dropped since the group's newest epoch's auth pin and time, so a leaf commits the Remove a wrapped rotation left".

**§10.6, the keys rule.** In the object table's note add: "§11.8's 'no key prefixes another' is a path prefix, so `<ref>` beside `<ref>.claim` stands."

**§10.7, KF2.** After "a committer per 10.9 claims a KeyPackage and commits the Add with other pending changes" add "(every Remove it may commit among them, so the new tree lies within the key holders at its pin)". KF5: after "resyncs by external commit" add "once its tree holds no dropped leaf but its own old one, waiting otherwise for a writer leaf's Remove, which gkm hints".

**§10.9, the roster row.** Replace with: "roster: every commit's new tree lies within the key holders at its auth pin, and in the config and directory groups within the leaf-entitled devices (§7.9), except a recovery self-join's revoked leaves (10.8), whose generation-0 epoch has no GenWrap; a committer checks this before it commits and carries every Remove it may, a leaf that may not commit one (read_only; an external commit) waits while its tree holds a dropped leaf, and a member refuses a commit that breaks it, never adopting its epoch and treating the generation its GenWrap carried as poisoned; so no epoch wraps a generation to a tree holding a party that generation excludes, and no leaf wrap uses such an epoch". Self-update row: add "deferred while the leaf's tree holds a dropped leaf it may not remove". External commit row: add "and waits under the roster row while its tree holds another dropped leaf".

**§10.11.** D-KEYS-18 gains "KF1 writes the group's owner marker before its form"; D-KEYS-24 gains "a Welcome pointer is keyed by (recipient, group, epoch)"; new **D-KEYS-27 (proposed):** "Every commit's new tree lies within the key holders at its pin, checked by the committer, which carries every Remove it may, and by every member; a leaf that may not commit a Remove waits while its tree holds a dropped leaf, and gkm hints writer leaves meanwhile. *Why:* an epoch that wraps a generation to a tree holding a removed leaf hands it the generation that excludes it, whatever honest members then do." New **D-KEYS-28 (proposed):** "A group belongs to one repo from its first byte: gkm/<group_id>/owner, created If-None-Match before the GroupForm, names the repo through which alone gkm resolves the group. *Why:* a form naming another repo's group would give a reader a write position there."

**§10.14, routes.** `POST /gkm/groups` and `/forms` gain "writes the owner marker first; 409 when it names a taken group id". The object list in Provides gains the marker and the pointer's key.

**§2.8.** gkm-1's `sees` gains "and each group's owner marker (repo_id, network_id)"; gkm-5's gains "pointers keyed by recipient, group and epoch, naming the KeyPackageRef the Add used".

**§22.7 and the FS rows.** The cases 6.6 names: FS-15, FS-20, FS-24, FS-103, FS-104, FS-6, FS-41, FS-97 and the committers block.

**§23.8.** No change: the fields freeze with the gkm wire at M2's exit (D-KEYS-10), these among them.

### 6.9 Owner questions

Each is filed under `.stack/questions/` in the brief's format, and the section was built on the recommendation in every case. The owner answered all six on 2026-11-10, each on its recommendation. Each answer follows its question, with its ledger id.

**details-6-last-resort-extension** (keys-m2-07-last-resort restated). Which extension marks a last-resort KeyPackage? Options: (1) draft-ietf-mls-extensions' `last_resort`, 0x000A, empty, as built; (2) a private-use type beside ur_group, 0xF554; (3) no extension, the route or key says. Costs: (1) a draft's number, moved by D-KEYS-12's migration if IANA changes it, and the one value OpenMLS sends; (2) stable, read by no other stack; (3) changes QD-526's accepted request and gkm-4. Recommendation: (1). **Answered: QD-616, option 1**, `last_resort` at 0x000A, as built.

**details-6-welcome-pointer-key** (keys-m2-13-last-resort-welcome-pointer restated). Options: (1) key pointers by group and epoch, `gkm/welcome/<sidecar_id>/<group_id>/<n>`, the ref inside the pointer; (2) `<ref>` for one-time and `<ref>/<group_id>` for last-resort KeyPackages; (3) keep the key, overwrite, and re-add after 10 minutes. Costs: (1) one key-form change, one proto field, gkm-5's wording; (2) two key forms and a path-prefix pair; (3) a lost Welcome per collision and a 10-minute delay. Recommendation: (1). **Answered: QD-618, option 1**, pointers keyed by group and epoch; KEYS-M2-19 carries the format change.

**details-6-group-owner-marker** (keys-m2-12-groupform-names-anothers-group, widened). Options: (1) an owner marker `gkm/<group_id>/owner` written If-None-Match before the form, the only binding gkm resolves by; (2) the question's option 1, a LIST before the form; (3) accept the reach. Costs: (1) one 40 B object per group, a §2.8 line under gkm-1 (no new value: the pair is already shown), one GET per group per process, and the landed LIST goes; (2) a LIST per form and a race between a repo's form and its epoch/0 in which two newest forms name one group and the resolver must refuse both; (3) any reader can wedge another repo's rotations. Recommendation: (1). **Answered: QD-614, option 1**, the owner marker; KEYS-M2-19, -21 and -25 landed it.

**details-6-claim-key-prefix** (keys-m2-13-claim-key-prefix restated). Options: (1) §11.8's rule means a path prefix and `sidecartest/fake_blobs.go` checks that; (2) move claims to `gkm/kpc/`; (3) exempt `.claim` in the fake. Costs: (1) one change in EVSB's file and a sentence in §11.8; (2) a key-form change and QD-442; (3) a special case. Recommendation: (1); until answered KEYS-M2-13's filter of the one report stays. **Answered: QD-613, option 1**, the rule means path prefixes. The fake's change and the filter's removal are a task in `.stack/plan/proposals/owner-answers-tasks.md`.

**details-6-ladder-aad-widths** (keys-ladder-aad-widths restated). Options: (1) as built, u64be for g and e, u8 for cause, gen/1 REQUEST; (2) u32be for cause; (3) gen/1's cause free. Costs: (1) text only; (2) one line and regenerated vectors; (3) a reader rule for two shapes. Recommendation: (1). **Answered: QD-615, option 1**, the widths as built.

**details-6-reform-epoch-zero-floor** (keys-wire-reform-epoch-zero restated). Options: (1) as landed, no auth at a re-form's epoch 0, epoch 1's floor from gen/<form.generation>'s auth; (2) a Signed GenRotate in the reform request; (3) epoch 0 through the epochs route after the ladder. Costs: (1) one sentence in the epoch PUT check; (2) the same bytes twice and a ladder check; (3) a special case on the epochs route and a third route in deleted mode. Recommendation: (1). **Answered: QD-617, option 1**, epoch 1's floor from the form's generation; KEYS-M2-25 landed it.

None blocked the held tasks: every one is additive before M2's freeze, and each task above was built on the recommendation.

Three questions the build tracks raised against this section were answered the same day, and the section now carries them. **keys-m2-23-large-group-memory: QD-641, option 1**, with the owner's direction that the SDK keep bulk state on storage: the engine is brought under the phone budget in the review phase by a tree held on disk and streamed, and 6.4's memory row gives the measurement in place of its estimate. **keys-m2-24-recovery-wrap-opens-before-admission: QD-642, option 1**: a code-only device fetches its recovery wraps before admission and opens them once admitted, in 6.2.4's Recovery. **keys-m2-19-members-skip-roster-twin: QD-644, option 1**: the poison rule is in `Gkm.tla` (6.3, 6.6).

Three more answers add rules in this area that this section does not restate. Each is a KEYS task in `owner-answers-tasks.md`, with its §10 text left to design-records. QD-638 (keys-m2-19-agent-created-repo-group, option 2): the group of a repo an agent creates is formed by the first member device that gkm's pending hint reaches, which runs KF1's steps 2 to 4 and wraps generation 1 to the agent. QD-643 (keys-m2-25-groupform-signer-judged-at, option 1): a GroupForm carries the signer's auth pin, and members judge its signer at that pin, which refines the Re-form paragraph's "members check the form's signer by §10.6's rule". QD-637 (keys-m8-01-delegation-key-batch-read, option 1): a batched read of forwarding Delegations' reader keys, at M8.

## 7. Remote search across designated indexers (§11.14, §18.4)

Status: pending

Tasks held until complete: SEARCH-M10-19, SEARCH-M10-32, SEARCH-M10-33.

## 8. Git and evs in both directions

Status: complete (2026-11-10)

Amended 2026-11-10 for the owner's answers: QD-604 (an import makes helper refs for a first-parent step too large for one push, where this section had refused it: 8.2.2, 8.2.6, 8.2.8, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8) and QD-632 (a new ref's path epoch; an overlay's first push takes its base ref's current epoch: 8.2.4, 8.2.10). 8.9 records every answer, QD-598 to QD-606 and QD-634. EVS1-M2-34, held for the first amendment, builds to this text.

Tasks held until complete: EVS1-M2-34, EVS1-M2-35, EVS1-M2-36.

Model: `sidecar/sidecartest/model/details/GitSync.tla`, its configurations (`GitSync*.cfg`, `GitSyncTwin-*.cfg`, `GitSyncReach-*.cfg`) and `run-gitsync.sh` beside it. New tasks: `.stack/plan/proposals/details-8-tasks.md` (EVS1-M2-48 and EVS1-M2-49). Questions filed: `.stack/questions/details-8-import-forms.md`, `details-8-history-blobs.md`, `details-8-pulled-sources.md`, `details-8-import-per-push.md`, `details-8-changeless-parts.md`, `details-8-overlay-directories.md`, `details-8-tag-refs.md`, `details-8-conflict-branches.md`, `details-8-import-step-bound.md`. Questions this section answers, each on the option 8.9 names: `evs-codec-import-forms`, `keys-m2-26-rekey-git-mode-refs`. Open questions this section builds on, each on its recommendation: `evs1-m2-01-ref-creation-fields` (option 1), `evs1-m2-24-root-directory-names` (option 1, as section 9 extends it).

### 8.1 The problem

§11.7 maps one git ref update to one evs push on a git-mode ref: the cleartext changes are the net change per path, the sealed metadata holds the commits, and the push commits only on the ref's tip. §11.11 puts stock git in front of that: a plain bare repository per mount, a pre-receive hook for owner decision 81's committer rule, a proc-receive hook that answers each ref after evs does, a journal, and a sync engine that replays other devices' pushes into the bare repository. EVS1-M2-32 (export) and EVS1-M2-33 (mounts, the bare repository, per-ref locks, the sealed mirror's layout) have landed as drafts. EVS1-M2-34 (git to evs), EVS1-M2-35 (evs to git) and EVS1-M2-36 (the receive path) wait on this section.

Terms. A ref's *tip* is its git value: a commit's oid, or an annotated tag's. An *update* is one (ref, old, new) triple git hands the daemon. A ref's *path state* is what evs's `idx/` entries say its files are. A reader of a ref *holds* an object when replaying the ref's earlier pushes put it in its object store. A *commitless version* is a version whose push moves no tip: a PATH_EPOCH push or a rekey. A *replaying reader* is the local tier's sync engine or export; head mode reads single files and checks no commit.

Working the three tasks through against the landed code and §11's rows found fourteen ways it goes wrong. Each is a scenario the design below must close.

**A. A commit's blob that is not in the net change is carried by nothing.** An agent commits twice and pushes once: c1 sets `plan.md` to blob b1, c2 sets it to b2. The net change is `plan.md` → b2, and the sealed metadata holds c1 and c2 with their changes as {path, mode, oid}. Nothing holds b1's bytes. Export stops with "a commit naming a blob no push carries" (`evs_export.go`), a second device's bare repository holds a c1 whose tree names a missing blob, and `git fsck` there fails, which is M2's twenty-agent exit check (§22.8). A file added and removed inside one push, and every blob of a merged side branch, fail the same way.

**B. An update that brings no commit has no value.** `EvsSealedMetadata` holds commits and nothing else about git, and export takes the last one as the tip. A branch created at an existing commit, a lightweight tag, a forced rewind to an ancestor and a DELETE carry no commit, so no reader can tell what the ref became. An annotated tag's object has no home at all: the codec knows blobs, trees and commits.

**C. Replay refuses the first pull.** §11.11's hook checks only *new* commits, "one that no ref of this repo's local mirror reaches". Replay has no such notion. An agent pulls `main`, which holds commits by two other sidecars, into its owned ref and pushes. Its hook passes: those commits are on `main`. The push's commits are everything its ref did not have, the others' included, and a replaying reader holds each to the decided rule (plan-CORE-client-to-sidecar-lookup #1 and #2): the committer is the push's `client_id`, or a client whose binding names the push's signer. The others' commits fail it, and every replaying reader alarms a forged history on the first merge of the twenty-agent test. Fast-forwarding `main` to a colleague's branch fails the same way. The hook's rule depends on the order pushes reached one device, and evs gives no order across refs, so a reader cannot simply copy it.

**D. Sealed metadata that outgrows its parts.** A push of 2,000 commits that touch 30 files holds about 1.1 MiB of sealed commits and 30 changes. Parts are cut by changes, sections with no change of their own "spill into the parts' room", and the builder stops with "section does not fit beside the changes" (`evs_statement.go`). A part with no change is refused (`evs_payload.go`). No push past about 1,800 commits can be sent.

**E. A committed push ends on a conflict branch.** §11.11's restart row: "committed -> update the local ref if it still equals old, else move the local commits to ur/<sidecar_id>/conflicts/<ref>/<time> and raise EvsConflict". A device pushes P, old → new. evs commits it, and the daemon dies before its `git update-ref`. At restart the sync engine sees the new version first, as it would any other device's, and moves the local ref to new. The journal then resolves P: committed, and the local ref no longer equals old, so it makes a conflict branch for a commit that is the ref's own tip and raises EvsConflict. `GitSyncTwin-EqualsOld` shows it in a trace of 7 states. On an owned ref, accepted locally at once, a second local push before P resolves gives the same.

**F. One lock cannot be both held across the push and free for sync.** The journal row reads as if the ref's daemon lock were held from the check of old to the `update-ref`. A push that waits its three minutes on GATE_CLOSED then stalls every other device's commits to that ref locally, and a receive that must replay the head to tell "only a PATH_EPOCH moved it" from "it gained a commit" waits on the sync engine, which waits on the lock. The landed lock's comment says the opposite, that the lock is taken only around the `update-ref`; then sync can apply the push's own version between evs's 200 and that `update-ref`, which fails its compare and lands in E.

**G. A push id cannot be retried after a restart, and "unknown" has two wrong answers.** The journal keeps {push id, statement hash}. A statement is sealed under random nonces, so a restarted daemon cannot send the same bytes again, and another statement under the same push id is 409 PUSH_ID_REUSED if the first committed. So "resolves each unfinished entry by retrying its push id" cannot be done as written. And while an attempt's outcome is unknown, answering `ng <ref> non-fast-forward` is false if it commits later (FI-9's per-ref outcome), which `GitSyncTwin-NgOnUnknown` shows, while a daemon that takes every movement of the head for another's commit answers non-fast-forward to its own committed push (`GitSyncTwin-NoRecognition`).

**H. An overlay cannot lose a path.** An agent branch is an overlay: it "writes only the paths it changes", and a path it holds no version of reads from its base. The agent deletes a file it inherited. A removal on base 0 is a removal of an absent path, which 5g and replay refuse. The parent's delta may remove the child's token, but the branch holds no table for that directory, and a fold's table "removes none". If a marker could be written, its collection (§11.7) would later delete it and the path would read `base` again. No overlay can express `git rm`, and no reader can list one.

**I. A split import cannot be checked, and its signature can be borrowed.** `EvsImport` signs {tip_oid, oid_list_sha256, count} for the whole import, and "an import past 1,024 parts splits at commit boundaries, each push carrying the EvsImport". A reader of the second of five pushes holds a hash of a list it has not seen, so it cannot tell whether a commit there is listed. If it waits for the last push it has accepted foreign committers on trust meanwhile; if it does not, any writer can attach the admin's EvsImport, which every reader of the repo can open, to its own push of commits with forged committers.

**J. History that stock git holds and the codec refuses** (question evs-codec-import-forms). A tree is never stored: a reader rebuilds it from names and each child's sealed {mode, oid}. A tree with a zero-padded mode, with a mode outside git's six, or out of git's order hashes to an oid no rebuild reaches. Stock git 2.56 stores all of them: `git index-pack` takes each, and plain `git fsck` passes the first two with warnings and calls the third an error without refusing to serve it. Old histories written by other tools hold them. A commit with a second `committer` header is stored too, and git 2.56's `git log --format=%cn` prints the *last* one, where the question records git and go-git as reading the first: exactly the two readings the codec's refusal exists to prevent.

**K. A large import does not fit its clocks or its memory.** Parts and the seal must reach evs within 30 minutes of the statement's `time_ms`, a receipt must be under 24 h old at the seal, and the seal lease lasts two minutes. A million-commit import is about 0.8 GiB of sealed metadata and entries and 7.4 GiB of segments (8.4). On a 5 Mbit/s uplink the parts alone take 23 minutes and the segments three and a half hours. Export keeps one map of every path per commit it rebuilt (`states`), which for 100,000 files and a million commits is 10^11 entries.

**L. Commitless versions under a waiting push.** A PATH_EPOCH push and a rekey move the version and not the tip. A git push built on the version before fails TIP. If only a PATH_EPOCH intervened it must be signed again with its sealed bytes kept (section 9's retoken). If a rekey intervened, the paths it re-checkpointed have new chains, and the waiting push's diffs cite the old ones, which 5h refuses. And `ur evs rekey` has no shape on a git-mode ref at all (question keys-m2-26-rekey-git-mode-refs): there is no tree change for a git push to carry.

**M. A queued update that evs will never take.** An owned ref is accepted at once: the local ref first, then the journal's push. "Refused -> drop the entry" leaves the local ref holding commits evs refused, for good: the sync engine cannot fast-forward a ref that has diverged, and nothing ever tells the user. `GitSyncTwin-RefusedDropOnly` reaches a state where nothing more can happen and the local ref is not evs's. The crash between the journal's append and the local `update-ref` is also unstated.

**N. Trees evs cannot hold as git has them.** A commit replaces the file `docs` with a directory `docs/`. One change names one token path, 5g refuses "a directory created over a standing path" and "a file written over a standing directory", and replay refuses "a creation of a path that stands", so the update cannot be stated in one push, and a git update is one push. A submodule link (mode 160000) is a file entry with no content, and `evs_payload.go` refuses a file entry with an empty chain, though `EvsSealedFields` takes the mode.

The requirement: every oid of an update, its commits', trees', blobs' and tags', is rebuilt exactly by every replaying reader, for any history stock git holds whose trees name files a path can name; no acknowledged commit is lost and no update is committed twice, whatever is killed and whichever answers are lost; a local ref never shows a tip evs did not commit, except an owned ref's own queue; descent, FORCE, DELETE and IMMUTABLE follow §11.8's table; PATH_EPOCH pushes and rekeys pass through without an `ng`; and a push's cost is bounded by what it changes, an import's by its history, within 1,024 parts a push.

### 8.2 The design

#### 8.2.1 The principle

Four ideas carry the section.

**A push carries exactly what its ref's readers do not hold.** For every push there is a set of objects its readers hold before it: everything the ref's previous tip reaches, everything an overlay's base tip reaches, and everything reachable from the tips of the *sources* the push names, which are committed versions of other refs of the repo. The push carries every commit and every blob its new tip reaches outside that set, and nothing inside it. A blob that the ref's new tree holds at a changed path rides in that path's entry version, as today. Every other carried blob is a *history blob*, one sealed record named from the sealed metadata. That closes A. A source is also what makes "a commit already in the repo" a fact a reader can check, which closes C: a commit a push carries is new to the repo and must be its signer's, and a commit that came from another ref is named by where it came from and not carried.

**A ref's value is stated, never inferred.** Every git-mode push but a PATH_EPOCH seals what the ref was and what it becomes. A push with no commit is then as well defined as any other (B), and a rekey is the update that states "no change" (L).

**Bytes that hash travel as bytes.** A commit travels as its object, as landed. A tree that does not rebuild from names, modes and oids travels as its object too, beside the changes that rebuild every other tree, and so does an annotated tag. Strictness moves from "what the codec can decode" to "what a new commit may be": a commit the pushing sidecar makes must be canonical, and imported history must only be history git itself can walk (J).

**The local tier is a replica of evs's log, and the journal records intent, not truth.** A device's state for a ref moves only by applying evs's versions in order, through one rule, under one short lock, whether the version is another device's push or its own. Two compare-and-sets carry safety: evs's TIP and git's `update-ref <new> <old>`. The journal says what the daemon meant to do and which push ids it sent. An outcome is read from the ref's history and nowhere else, so no crash, lost answer or late attempt can make the journal wrong in a way that moves a ref (E, F, G, M).

What does not change: one evs push per git ref update; TIP for every git-mode push; the seal lease; §11.8's refs table; the hook's rule in §11.11's own words; the journal as D-EVS-28 has it, resolved by push id; `ur/<sidecar_id>/conflicts/<ref>/<time>` and its `<time>` form (plan-EVS1-ref-name-bytes #2).

#### 8.2.2 Formats settled

Format 1 is unfrozen. Numbers are next-free in `sidecar/protocol/evs.proto` on 2026-11-10.

```proto
message EvsSealedMetadata {
  ...                                   // 1 group, 2 provenance, 3 commits, 4 signed_import, as landed
  EvsGitUpdate git = 5;                 // git mode, every push but a PATH_EPOCH: what the update is (8.2.3)
  bytes ref_name = 6;                   // a creating push: the ref name's bytes, the signed copy of payload section 15
  EvsOverlay base = 7;                  // a creating push of an overlay: the signed copy of payload section 16
}
message EvsGitUpdate {
  EvsGitShape shape = 1;
  bytes old_tip = 2;                    // the ref's value before: 20 B, or empty for none (never created, or deleted)
  bytes new_tip = 3;                    // its value after: 20 B, or empty for a DELETE; a REKEY sets neither
  repeated bytes tags = 4;              // new_tip's annotated tag objects, outermost first, each one's `object` the
                                        // next one's oid and the last one's a commit; none when new_tip is a commit
  repeated EvsOverlay sources = 5;      // committed versions of other refs whose tips this push's readers hold; <= 16
  repeated bytes segment_ids = 6;       // the segments holding this push's history blobs, each among its new objects
  repeated EvsSealedBlob blobs = 7;     // history blobs, each after the blob it is a diff of
}
enum EvsGitShape { EVS_GIT_SHAPE_UNSPECIFIED = 0; EVS_GIT_UPDATE = 1; EVS_GIT_DELETE = 2; EVS_GIT_REKEY = 3; }
message EvsSealedBlob {
  bytes git_oid = 1; uint64 size = 2;
  bytes base_oid = 3;                   // empty: one checkpoint record, or chunk records; else the blob its one
                                        // diff record applies to, which its readers hold by then
  bytes file_id = 4;                    // 16 random bytes, the records' AAD; one history blob, one file_id
  repeated EvsHistoryLocator records = 5;
}
message EvsHistoryLocator { uint32 segment = 1; uint32 offset = 2; uint32 length = 3; }  // segment: index into segment_ids
message EvsSealedCommit {
  bytes object = 1;                     // as landed
  repeated EvsSealedChange changes = 2; // as landed: against its first parent, sorted by path
  repeated EvsSealedTree trees = 3;     // each tree of this commit that differs from its first parent's at that path
                                        // and does not rebuild from its children's names, modes and oids
}
message EvsSealedTree { repeated bytes path = 1; bytes object = 2; }  // the directory's names (none: the root), its bytes
```

`EvsSealedChange` keeps its fields; its `mode` is the entry's mode as git reads it (below). `EvsImport` keeps its fields and changes meaning (8.2.6): it signs one push's commits, not an import's.

Rules, for `protocol/EVS-FORMAT.md`:

```text
commits    the carried commits (8.2.3), parents before children, each object's SHA-1 its oid
changes    a commit's changes are the files that differ between its tree and its first parent's (none: the empty
           tree), each {path, mode, oid}, a removal with no oid, ascending by path bytes; mode is canon(m): 100644,
           100755, 120000 or 160000 by git's canon_mode, and 100664 kept; a directory is never a change
trees      a tree object is canonical when it is what EvsGitTree.Encode gives for its entries; a commit's `trees`
           holds every tree of it that is not canonical, unless its first parent holds that object at that path
history    a history record is a checkpoint, a chunk or a diff (11.6's record, 160 B header); its header's
           base_record_id is zero, since its base is named by oid; it sits in a segment of the push, and no entry
           version's chain names it
gitlink    a file entry whose sealed mode is 160000 has an empty chain, size 0 and the link's oid; no other file
           entry has an empty chain; evs takes both, and a reader refuses the mismatch
kinds      on a git-mode ref a change may write a file where a directory stands and create a directory where a file
           stands: it is a creation (base_entry_version 0), and the push removes every path below a replaced
           directory by its own changes; on a file-mode ref both stay 409
versions   on a git-mode ref a creation's version is its push's effective base version + 1, which TIP makes
           max(b, m) + 1 (every earlier version is at most b)
parts      a part may hold no change when it holds a slice of a spilled section: such parts come after every part
           that holds a change, carry no changes_root and are no leaf of the statement's root; parts_sha256 covers
           them as it covers every part; evs runs steps 4 and 5 for none of their entries, having none
sections   payload section 15 (the ref name, sealed under manifest_g, AAD "UR evs 1.0 ref name" || repo_id ||
           ref_id) and 16 (an EvsOverlay) ride only in a push that creates its ref or is the first after a DELETE
           (question evs1-m2-01-ref-creation-fields, option 1); the first after a DELETE repeats the head's base
```

Local state. Everything is in the evs component's sealed directory, under `local/<repo_id>/`, beside `mirror/` and `mounts/`:

```text
ref/<ref_id>              EvsGitRef: name; version, chain; tip; applied_tip; deleted; base (ref, version); stuck_at;
                          a tag's peeled commit; tainted token paths (8.5)                 (8.2.7)
tips/<ref_id>/<page>      the version-tip log: 4,096 versions a page, each {version, tip, flags}, appended as
                          versions apply; commitless versions are left out (the tip before stands)
tipindex/<oid[0:2]>       commit oid -> (ref_id, version) for every tip a ref version had, 256 sorted files
held/<ref_id>             an overlay's held paths: path -> file, directory or removed, as a base file and a log of
                          the versions since, folded every 64 (8.2.4)
born/<ref_id>             section 9's born journal, fed by replay (8.2.10)
journal/<ref_id>          EvsJournalRef (8.2.8), rewritten whole
import/<id>               an import's arguments and its helper refs, so a rerun resumes it (8.2.6): EvsImportRecord
                          {dir, source tip, dst, cuts, force, helpers: {n, merge, parent, under, ref_id, state}}
```

In the bare repository the daemon keeps `refs/ur/evs/<ref_id hex>` at each ref's tip as evs holds it, a deleted ref's at its last tip, and `refs/ur/import/<id>` at an import's source tip. `transfer.hideRefs refs/ur` keeps them from clients, in what git advertises and in what it lets a client push.

Settings, in `EvsSettings`:

```text
ReceiveWaitTimeout         3 min    time an update may spend waiting on evs to take what it refused for now
ReceivePublishTimeout      30 min   time an update may spend building, uploading and posting
ReceiveRefCount            4        updates of one git push published at once
QueueFirstDelay            250 ms   an owned ref's first push after a local update (11.11)
QueueInterval              2 s      then at most one push per ref this often (11.11)
JournalResolveMargin       15 min   added to an attempt's time bound before it is taken for dead without the head
                                    having moved (8.2.8)
OverlayBaseSearchCount     10,000   first-parent ancestors searched for an overlay's base
ReplayBatchVersionCount    64       versions replayed between two settles
ObjectSinkChunkByteCount   64 MiB   objects written between two packs
TreeCacheByteCount         64 MiB   trees the builder keeps
ImportPushPartCount        512      an import cuts a push here (the bound is 1,024)
ImportPushByteCount        32 GiB   and at this much sealed content
ImportPostTime             10 min   and where its parts would take longer to post at the rate measured
ImportCommitEstimate       1 KiB    sealed metadata assumed per commit before it is built
ImportStepPartCount        960      a first-parent step past this many parts is oversized (the bound is 1,024)
ImportStepPostTime         20 min   and one whose parts would take longer to post (a statement's bound is 30 min)
ImportStepUploadTime       18 h     and one whose content would take longer to upload (a receipt serves 22 h)
ImportHelperCount          64       helper refs one import may make
ImportHelperDepth          8        helper refs nested one inside another
ConflictBranchCount        64       conflict branches a ref may have before its sync stops
GcMinInterval              24 h     between two git gc runs of one mount
```

#### 8.2.3 What a push carries

A git-mode push is one of four shapes. evs sees the flags and the changes; the shape is sealed.

```text
shape       flags                       commits  changes                          tip
UPDATE      FORCE when new does not     0..n     the net change of the path       old_tip -> new_tip
            descend from old;                    state (8.2.4); none on a tag ref
            IMMUTABLE on a tag's creation
DELETE      DELETE                      none     none                             old_tip -> none
REKEY       none                        none     file entries only: the same      unchanged; no tip stated
                                                 mode and oid, a fresh checkpoint
PATH_EPOCH  PATH_EPOCH                  none     none (section 9)                 unchanged; no git field
```

For an UPDATE of ref r from old to new at base version b:

```text
excl      old (when r has a tip); the tip of r's overlay base at its base version (when r is an overlay)
evs tips  refs/ur/evs/*: the tip of every other git-mode ref of the repo as the mirror has applied it, a ref with
          queued commits at the tip evs holds and never at its local ref
carried   C = git rev-list --topo-order --reverse --boundary <peel(new)> --not <excl> --glob=refs/ur/evs/*
          less its boundary lines
sources   for each boundary commit that excl does not reach, in C's order, and for peel(new) itself when C is
          empty and excl does not reach it: the ref whose refs/ur/evs/ tip reaches it (git for-each-ref
          --contains), a shared ref before an owned one, then the most recently applied; S is those refs, each
          with the version the tips log gives its tip; at most 16: past that C is taken again against excl and
          tips(S) alone, and what it gains is carried, and must then be this sidecar's own
blobs     B = the blobs git rev-list --objects <peel(new)> --not <excl> <tips(S)> lists: every blob C's changes
          name that the readers do not hold, and at times one an old held commit has, which is carried again
```

Every commit a tip of S reaches is reached through a boundary commit, so C is exactly the commits no reader holds once S is replayed. Every commit of C is carried in `commits`, in that order. Every blob of B is carried once: by the entry version of a path whose new blob it is, else as a history blob. Nothing else is carried, and the push names S.

A history blob is sealed as one record:

```text
for c in C, in order; for each change of c that names a blob o in B, in path order; o not yet placed:
    o is the new blob of a net-changed path (8.2.4):       its entry carries it; skip
    p = the blob at that path in c's first parent, if any and if both sizes are at most DiffMaxByteCount:
        delta = EvsGitDeltaEncode(p, o); if |delta| < |o|:  a diff record, base_oid = p
    else:                                                   a checkpoint record, or 4 MiB chunks above 8 MiB
    file_id fresh; the record appended to the open history segment (8 MiB, Padmé-padded, uploaded with ?push=P)
```

The base p is always held by then: c's first parent is in C before c, or outside C and so in what the readers hold, and a blob of its tree is carried earlier in the list, carried by an entry, or held. There is no chain, so no chain bound and no periodic checkpoint: a reader that rebuilds git objects holds every base as a whole blob.

Tags. `new` may be an annotated tag's oid. `tags` then holds the tag objects from `new` down, and peel(new) is the commit the last one names. A tag of a tree or a blob is refused before any evs write (`ng <ref> tag of a non-commit`; 8.9).

What a new commit may be. A carried commit that no `EvsImport` covers is *new*. The hook (8.2.8) and every replaying reader hold it to the same rule: its object is canonical (`EvsGitCommitDecode`), its committer is a strict ident whose email is `<client_id>@ur.invalid` with client_id the push's own or one whose binding names the push's signer (plan-CORE-client-to-sidecar-lookup), and every tree it brings is canonical, so a new commit never needs `trees`. The hook judges this C, which is §11.11's "no ref of this repo's local mirror reaches" read as "no ref evs holds": a commit that is only on this device's queue is carried, and is this sidecar's own.

#### 8.2.4 The path state: branches, overlays and tags

```text
tag ref    (name bytes begin refs/tags/): no path state and no base. Its one push is created IMMUTABLE and
           carries no change; what its commit reaches is held through the push's sources, and anything beyond
           is carried, every blob a history blob. So a tag of anything a ref already reaches costs one empty
           push. evs's reads of a path there mean nothing and no client asks; head mode names no ref (§18.5)
           and replaying readers use the commits.
branch     with no base: its path state is tree(peel(tip)), every file and every directory, the root included
           (section 9's EVS1-M2-46). After a DELETE the entries stand as the last tip left them, and the push that
           re-creates the ref states its net change against that tree.
overlay    a branch with a base (ref R, version k): it holds entries only for *held* paths:
             a file is held once the overlay wrote it (a change, or a removal while it held it)
             a directory is held whole or not at all: the first push that adds or removes a child of D writes D
             as a creation whose delta lists every child D has in the new tree; later pushes send deltas
           and its path state reads, for a path X:
             the overlay's standing entry for X                                  -> that
             else, from the root down, for each ancestor directory A the overlay holds: the next name of X is
             not in A's table                                                    -> absent
             else                                                                -> R's path at version k
```

A held directory's table is the whole truth about its children, so an inherited file is removed by a table that lacks it, and the removal survives a marker's collection and a path-epoch copy, which carry tables and drop markers (H). A file whose content the overlay changes without adding or removing a name needs no directory at all. A reader resolves a path with one request naming it and its ancestors on the overlay, then the base when it must; the local tier never does, since it holds the trees. A repo's refs share their path keys (§11.6), so an inherited name's floor on the overlay (9.2.3) is its floor on the base ref, and a held directory's first table, which lists inherited children, sends no token the floor rule forbids.

The base of a new branch whose tip is T, chosen by the device that creates it:

```text
candidates   the first ancestor of T on its first-parent line, T included, within OverlayBaseSearchCount, that the
             tip index holds as a branch's tip: its (ref, version)
             each other branch's applied (ref, version) whose tip is T or an ancestor of T
choose       the candidate whose tip leaves the fewest commits (git rev-list --count T --not tip); ties: a shared ref
             before an owned one, then the lower ref id, then the lower version
none         no candidate: the ref has no base and holds its whole tree
```

A base is a branch, never a tag ref, and it never changes. It is where the overlay's unheld paths read from, and its tip's tree is the tree the overlay's first push states its changes against. The overlay's first push also takes the base ref's current path epoch as its own (8.2.10; QD-632), so at its creation an overlay's token paths are its base's.

The net change of an UPDATE on a branch, from the tree the path state stands at (S: old's, a deleted ref's last tip's, an overlay's base tip's for its first push) to tree(peel(new)) (N), by the tree reader of 8.2.5:

```text
file in N, not in S, or with another mode or oid:   a write: base_entry_version from the read below, 0 creating
file in S, not in N:                                 a removal, on an overlay only if the file is held, else the
                                                     parent's table drops it
directory in N whose child names differ from S's:    a delta; a creation with every child when the directory is new
                                                     or an overlay first holds it
directory in S, not in N:                            a removal (its files are removed by the rows above; a
                                                     directory the overlay does not hold is dropped by its parent)
a path that is a file in S and a directory in N, or the reverse: a creation of the new kind (8.2.2's kinds row)
the root:                                            a delta, when a top-level name comes or goes
```

Entries are planned by the landed planner (`evs_plan.go`), which gains a git-mode entry point, `PlanGitUpdate`, taking this list in place of `EvsPathWrite`s:

```text
reads      each changed path's standing entry on r is read from evs, 64 a request, under section 9's floors; a ref
           with no head reads nothing: every change is a creation at version b_eff + 1
content    a write's new bytes and its previous version's bytes come from the bare repository by oid, hashed as
           they are read; a miss falls back to reconstruction from evs, as file mode does
chain      the planner's rules unchanged: a diff against the path's previous entry, or a checkpoint by rules (1)
           to (4); a file past 8 MiB in chunks; an inline chain to 16 KiB
rename     a removed path A and a created path B with one blob oid, in one push: B takes A's file_id and chain
           (5h's "a path the push removes"); several candidates pair in path order
reuse      an overlay's first write of an inherited path whose base entry holds the previous blob: a diff citing
           the base's chain, with a reuse item for (R, that entry version); a path whose new blob is the standing
           entry of the same path on a source ref: its chain cited whole, with a reuse item; when 5h refuses a
           reuse (the entry moved on) the path is planned again as a fresh checkpoint
gitlink    mode 160000: sealed fields only (8.2.2)
versionless never: versioning is 0 on every git-mode entry
limits     32 components, 4,096 children and 448 KiB of names a directory (§11.19), checked on N before any evs
           write: `ng <ref> DIRECTORY_FULL <path>`; one update writes at most 1,048,576 entries
```

#### 8.2.5 Building and sending an update

One function serves the receive path, an owned ref's queue and an import: `EvsLocalPublish(ref, old, new, options)`. Its caller holds the ref's publish lock (8.2.9) and read `old` and the base version b from the ref's `EvsGitRef` under the apply lock.

```text
publish(r, old, new, opt):
  1 shape, flags, base, sources, C, B                              (8.2.3, 8.2.4); a DELETE skips to 6
  2 per c in C, streaming, commits to a spool file:
        new commit: the strict checks of 8.2.3, else refuse; imported (opt.Import): graph decode only
        changes(c) = diff(tree(first parent), tree(c)) by the tree reader; trees(c) = its non-canonical trees
  3 net change (8.2.4); PlanGitUpdate; entries sealed, their segments uploaded (the landed sender)
  4 history blobs sealed into history segments and uploaded, 4 at once, each under its receipt
  5 sealed metadata: group, provenance (the session's agent, §5.5), commits (from the spool), git,
        signed_import, and for a creating push ref_name and base; payload sections 15 and 16 beside it; the
        reuse list
  6 statement on (b, C_b); the journal records its push id before the first POST (8.2.8)
  7 a one-part push posts; a push in parts takes the seal lease, posts its parts 4 at once, takes the lease again
        each time it lapses (evs answers 200 for a live lease of the push's own), and seals
  8 the answer:
        200 {v}                 apply version v from the bytes sent, through 8.2.7's replay, and settle
        409 non-fast-forward    replay r to its head, then:
                                  the history holds this push id            -> as 200
                                  only PATH_EPOCH versions since b          -> section 9's retoken on the new base
                                  a REKEY since b, the tip unchanged        -> build again from step 3, a new push id
                                  the tip moved                             -> the caller's (8.2.8): ng, or the queue's
        412 PATH_EPOCH          section 9's retoken
        409 SEGMENT_STALE, SEGMENT_GONE, SLOT_STALE, TIME_STALE; 412 GATE_CLOSED
                                the landed rebuild: a new push id, sealed again, uploads kept while under 22 h old
        409 PARTS_MISSING       post the part again and seal again
        429, 412 PATH_EPOCH_DUE, a lease another push holds
                                wait retry_after_ms, within the caller's wait bound
        503 unknown, no answer  the same statement again while this process lives; then 8.2.8's resolution
        any other refusal       the caller's, by its code
```

The tree reader is the one place the local tier reads a tree, and it reads what git reads:

```text
readTree(oid):  the object's bytes from `git cat-file --batch`; entries by git's decode_tree_entry: octal digits, a
                space, a name to the NUL, 20 B; kept as {mode as written, name, oid} with canon(mode)
                refused, naming the tree: a name that is empty or holds a slash; two entries of one name
diff(a, b):     a merge walk of the two trees in name order (each sorted by name bytes first, since a raw tree
                may be out of order), descending only where the oids differ
```

It never calls `git diff-tree`, whose walk assumes git's order. A refusal here refuses the update, or the import, before any evs write, naming the object.

#### 8.2.6 Imports

`ur evs import <dir> [<ref>]` brings history whose committers are not this sidecar's. It is run by a repo admin's device, by the daemon itself and not through the hook, and it ends as ordinary pushes.

```text
import(dir, srcRef, dst, cuts, force):
  refuse   a sha256 <dir>; a caller that is no repo admin at its newest verified state; dst a shared ref that has
           a tip this import did not put there; dst an owned ref of another sidecar, or a ref under
           ur/<this sidecar>/import/; a source tip that does not descend from dst's, without force
  fetch    git fetch --no-tags <dir> <srcRef>:refs/ur/import/<id>, into the bare repository, with no fsck
  record   local/<repo>/import/<id> {dir, the source tip, dst, cuts, force, helpers: none}: a rerun of the
           command resumes it; <id> is 8 random bytes drawn here, written as 16 hex digits
  run(dst, the source tip, cuts, force, depth 0)
  finish   clean (below); then delete refs/ur/import/<id> and the record

run(d, T, cuts, force, depth):                 brings ref d to tip T by ordinary import pushes
  loop     t = d's tip as replayed (none at first); stop when t is T
           walk T's first-parent line from the first commit that descends from t (every one, at first), a step
           at a time; step j is what c_j brings that c_(j-1) and evs's other tips do not hold:
           rev-list --topo-order --reverse c_j --not c_(j-1) --glob=refs/ur/evs/*
             before a step: |step| x ImportCommitEstimate would pass a soft bound and the push is not empty -> cut
             after a step:  the push passes ImportPushPartCount, ImportPushByteCount or ImportPostTime, or c_j is
                            one of `cuts` -> cut
             an oversized step: cut before it and send that push, so d's tip is c_(j-1); split(d, c_j, depth);
                            then take step j again
             a tip tree change past 1,048,576 entry writes: stop the import, naming c_j
           the push: EvsImport {repo_id, ref_id, tip_oid = the cut, oid_list_sha256 = SHA-256 over the push's
           carried commit oids in carried order, count}, signed by this admin, in signed_import;
           publish(d, t, the cut, Import), FORCE on the first push when force
```

An `EvsImport` therefore covers exactly the commits of the push that carries it, and a reader checks it against that push alone (I): the hash over the push's own commit oids, the count, the tip, the ref, and a signer who is a repo admin at the push's authorization pin. With one present every carried commit is imported: none is held to the committer rule or to the strict commit codec, and its trees may be raw. A push cannot mix imported commits and new ones. Each import push is an ordinary descending update, so the ref is usable between pushes, a killed import leaves a ref at a real commit, and a rerun continues from the ref's tip with nothing remembered but the arguments and the helper table below.

**A step too large for one push** (question details-8-import-step-bound, option 2; QD-604). One step of the first-parent line is one commit and everything its other parents bring, and a ref has one tip, so a step cannot be cut. A push does not carry what another ref of the repo already holds (8.2.3). So when a step would pass a push's bounds the import first puts the merged side into a ref of its own, a *helper ref*, by the same `run`, and the step then carries the merge commit and names the helper as a source. A side that has such a step of its own gets a helper inside its helper.

```text
oversized(step)   one push cannot hold it: by ImportCommitEstimate before it is built, or by its sealed bytes
                  once it is, it would pass ImportStepPartCount parts, its parts would take over
                  ImportStepPostTime to post at the rate measured, or its content over ImportStepUploadTime to
                  upload; nothing of an oversized step is sent

split(d, c, depth):                            c is the commit of d's first-parent line whose step is oversized
  while step(c) is oversized:
      q = the parent of c, after its first, that alone brings the most:
              own(q) = rev-list --count q --not <c's first parent> --glob=refs/ur/evs/*
      stop the import, naming c and the bound, when: no parent brings a commit (the step is c alone and
              what it changes, or its sources pass 8.2.3's 16); depth is ImportHelperDepth; the record
              already holds ImportHelperCount helpers
      h = the record's helper for (c, q): the one with that pair that is not abandoned, else a new one
              {n: the next number from 1, merge: c, parent: q, under: d, state: open}, the record written
              durably before anything is sent for it
      run(ur/<sidecar_id>/import/<id>/<n>, q, no cuts, no force, depth + 1)
      h.state = done, with the helper's ref id; refs/ur/evs/<its ref id> is at q now, so step(c) no longer
              holds anything q reaches
  the step's push is built as any: 8.2.3 finds the helpers among the refs whose tips reach its boundary
  commits and names each at the version the tips log gives its tip

clean:   for each helper of the record whose state is open or done, the most deeply nested first:
             publish(the helper ref, its tip, none), a DELETE push; then its state is deleted
```

A helper ref is `ur/<sidecar_id>/import/<id>/<n>`: an owned ref of the importing sidecar, a git-mode branch, `<id>` the import's and `<n>` a decimal number in the order helpers are first needed. Nothing about it is new to evs or to a reader. Its first push creates it as any new branch is created: 8.2.4 chooses its base, an overlay of the nearest branch tip its side descends from, and none when the side shares no commit with a ref evs holds, in which case it holds the side's tree as entries; 8.2.10 gives its path epoch. Its pushes are import pushes, each with its own `EvsImport` for the helper's ref id. A replaying reader that meets the step's push replays the helper to the named version first, as for any source (8.2.7), and holds what the side reaches before it checks the merge.

The import holds one publish lock at a time: P_d around each push to d and no longer, so a sub-import runs with no lock of the ref above it held, and 8.2.9's order stands. The receive path refuses a client's update of a ref under `ur/<this sidecar>/import/`, but its deletion (8.2.8), so nothing but the import moves a helper while it is in use.

Cleanup. When dst is at the source tip the import deletes every helper with a DELETE push, which its sidecar may send for an owned ref (§11.8's refs table). evs keeps a deleted ref's versions, push records and segments: a DELETE is one more version, and nothing collects a retained push's objects (G11). So a push that names a helper's version as a source stays replayable for good: `replay(helper, upTo that version)` reads the versions below the DELETE as it did before it. What the DELETE removes is the ref from listings, from `git ls-remote` and from each device's `refs/heads/`. The helper's entries stand as its last tip left them (8.2.4), and each mirror's `refs/ur/evs/<ref id>` stays at that tip, which keeps the side's objects from `git gc` and its commits out of later pushes. A helper is deleted only at the end, so that every push of the import that names one was committed first.

Resume. The record is the only new state. A rerun walks again from each ref's tip: a helper that is done is found by its pair and its tip is q, so `run` returns at once; one that is open continues from its own tip; one whose ref a rerun finds deleted while still open (its owner deleted it mid-import) is marked abandoned and the pair gets a new number; a kill inside `clean` leaves helpers marked done whose refs the rerun deletes, a DELETE of a ref evs already shows deleted being skipped. A kill between a helper's record entry and its first push leaves an entry with no ref, which the rerun creates. If `local/<repo>/` is lost the record goes with it: a new import of the same history makes new helpers under a new id, carries only what the old ones' tips do not hold, since the mirror replays every ref of the repo it learns of, and the old helpers are left as owned refs no record names, which `ur status` lists as leftover and their owner removes with `git push --delete`.

`ur evs import --abandon` ends an import that will not be finished: it runs `clean`, deletes `refs/ur/import/<id>` and the record, and leaves dst at the cut it reached. `ur status` shows an unfinished import with its dst, the cut reached and its helper refs.

What stays a hard bound, refused before any evs write for the step, naming the commit: one commit that changes more than 1,048,576 entries; a step that needs more than 16 sources (a merge of more than 16 sides, each too large to carry); more than `ImportHelperCount` helpers or `ImportHelperDepth` levels.

What an imported history must be is what git can walk and a path can name:

```text
carried as bytes   any commit git parses: `tree` first, then its `parent` lines (commit.c's parse_commit_buffer);
                   late or repeated author, committer, tree or parent headers; idents fsck refuses; a NUL in a
                   header; no blank line
carried raw        a tree with zero-padded modes, modes outside git's six (read by canon_mode), or entries out of
                   git's order
refused            a tree entry whose name holds a slash, or two entries of one name: no path can name them;
                   a tag of a tree or blob; a sha256 repository (plan-EVS1-format-bytes #4);
                   a tip tree past §11.19's directory limits (history may pass them: only a push's tip is entries)
```

After an import, `git push --tags` from the working clone creates each tag ref with no new commit and no change (8.2.4), and another branch of the same history is its own `ur evs import` when it holds foreign commits, an overlay of the nearest tip. `cuts` lets the caller put a tip where a later branch forks. `cuts` apply to dst's own first-parent line; a helper takes none.

#### 8.2.7 From evs to git: replay, verify, apply

A mount follows every git-mode ref of its repo that it learns of: `main`; a ref a local push creates; a ref a hint names, whose name the head's sealed ref name gives; a ref a push names as a base or a source, which is replayed for its objects even before its name is known; and, once EVS1-M6-01 serves it, the listing of GET .../refs. A branch `<b>` is `refs/heads/<b>` in the bare repository and a tag keeps its name (`EvsGitRefOfName`); a file-mode ref has no git ref. The sync engine keeps, per git-mode ref, an `EvsGitRef` and runs one replay at a time for it:

```text
replay(r, upTo):                                   // on a hint, the hourly resync, a push's answer, a start
  H = the verified head (EVS1-M2-23, EVS1-M2-27); m = EvsGitRef.version
  statements m+1..min(H, upTo), from the hint, the window or GET .../log; the verifier walks them: signatures,
      TIP, pins, §11.8's refs table (FORCE, DELETE and IMMUTABLE by scope and kind)
  for u in order:
      PATH_EPOCH        the epoch state and the born journal (8.2.10); no object
      else              the push's record and parts (§11.9's push reads; an own push: the bytes sent); the sealed
                        metadata under manifest_g; check(u) below; objects into the sink
      every ReplayBatchVersionCount versions, at ObjectSinkChunkByteCount, and at the end:
                        flush the sink; then, under r's apply lock: tips log, tip index, held, born and
                        refs/ur/evs/<r>; EvsGitRef {version, chain, tip}; settle(r)
  a refused u:          evs_alarm (version_rule, or tamper for a hash); EvsGitRef.stuck_at = u; nothing past u-1
                        is applied, and the local ref is left alone (8.5)
```

`check(u)`, for a branch or tag ref whose tip before u is E:

```text
every shape   git present; shape, flags and ref kind agree (8.2.3's table); a tag ref's first push IMMUTABLE and
              no other; ref_name and base only where the push creates the ref, equal to the head's
DELETE        no commit, no change; old_tip is not checked, since a stopped ref's deleter does not hold it (8.5);
              the tip becomes none
REKEY         no commit, blob, tag or source; every change a file entry whose opened mode and oid are those of
              tree(peel(E)) at that path; a tag ref takes none
UPDATE        old_tip = E
              sources: each a git-mode branch or tag ref of this repo other than r, at a version at least 1 that
              has a tip: replay(r', v') first; a ref that cannot reach v' leaves r waiting, and a cycle of
              waits refuses u
              commits: each hashes to its oid; its parents are held or earlier in the list; one already held
                  (two refs pushed the same commit at once) is judged the same and written once
              no signed_import: each commit is new and passes 8.2.3's rule (canonical object, strict committer,
                  the push's client or a client of its signer; SidecarCommitter refuses what it cannot resolve)
              signed_import: 8.2.6's check; nothing else is asked of its commits
              trees: tree(c) = build(tree(first parent), changes(c), trees(c)) equals the tree c names
              blobs: every blob a change names is held, or carried by an entry of this push (reconstructed, its
                  oid checked), or a history blob (base held, the record opened, its oid checked; one already
                  held is skipped)
              tags: each hashes to its oid; `object` and `type` chain down to a commit
              new_tip peels to a commit held or carried, and every carried commit is its ancestor
              descent: E is none, or FORCE is set, or E's commit is an ancestor of peel(new_tip)
              changes: on a branch, exactly 8.2.4's net change from the path state at E to tree(peel(new_tip)),
                  each entry's opened mode and oid the tree's, and beside it a write or a removal of every
                  tainted token path (8.5); on a tag ref, none
```

The tree builder and the object sink are shared with export (EVS1-M2-49):

```text
build(parent tree, changes, raw):
   group the changes by directory; from the deepest directory up: load the parent's tree for it (the cache, the
   sink's pending objects, else git cat-file), apply the changes, drop an emptied directory from its parent;
   a directory with a raw tree in `raw`: its entries, read as git reads them, must equal the built ones (names,
   canon modes, oids); then its oid is the raw object's and its bytes the raw bytes; else its bytes are the
   canonical encoding; an unchanged directory keeps its oid, raw or not, since nothing below it changed
sink:
   objects appended to a pack (version 2, undeltified, zlib), an in-memory index of the pending ones; at
   ObjectSinkChunkByteCount or a flush: `git index-pack --stdin` into the bare repository, which checks every
   hash again; export's sink writes loose objects as landed
```

Memory is the tree cache, the pending chunk and one commit's changes. Nothing is kept per commit, which replaces export's `states` map (K).

**Settle** is the one rule that moves a local ref. It runs under the ref's apply lock whenever `applied_tip` differs from `tip`, and at every start:

```text
settle(r):     E = EvsGitRef.tip (none: deleted); A = EvsGitRef.applied_tip; L = the local ref, read now
               Q = the journal holds queued updates for r, LOCAL or SENT, and the newest one's new is L (an owned
                   ref's queue)
               "ancestor" is of the peeled commits, and none is an ancestor of every commit
   L = E                                              -> nothing
   E = A and (Q or L = A)                             -> nothing: evs has not moved
   L = A, or L is an ancestor of E                    -> follow: git update-ref <r> <E> <L> (delete when E is none)
   Q, and E is an ancestor of L                       -> keep: the queue publishes L on the new tip
   else                                               -> conflict (below), then follow
   applied_tip = E; journal updates whose new is E or an ancestor of it are deleted
```

It is written in two steps, `EvsGitRef {version, tip}` first and `applied_tip` after the `update-ref`, so a crash between them is found by the difference and the rule runs again on the same inputs. A push of this device takes the same path as any other: its 200 leads to a replay of its version and a settle, and sync may get there first with the same result.

**Conflict branches.** A conflict is a local ref holding commits that evs's ref does not hold, when evs's ref has moved elsewhere or will not take them: an owned ref whose sidecar's state was restored or copied; a queued update evs refused for good (M); a ref moved outside the daemon.

```text
conflict(r):   one git update-ref --stdin transaction:
                   create refs/heads/ur/<sidecar_id>/conflicts/<r's name bytes>/<time> <L's commit>
                   update <r> <E> <L>        (delete when E is none)
               <time> is UTC yyyymmddThhmmssZ, a second later while the name is taken
               r's journal updates are deleted; a queue update (LOCAL) is added for the conflict branch
               SidecarEvent evs_conflict {RepoId, RefId: r's, Path: the conflict ref's name}
lifecycle      a conflict branch is an owned ref of this sidecar like any other: the queue publishes it, as an
               overlay of r, so the commits are safe off the device and visible to the member's other devices;
               nothing merges it, moves it or deletes it but its owner, with stock git (D-EVS-8);
               `ur status` lists each until its ref is deleted
bound          a ref with ConflictBranchCount conflict branches stops settling (its local ref is left alone) and
               `ur status` says so, until one is deleted
tags           a local tag that differs is replaced by evs's; its commit is saved only if no ref reaches it
```

A conflict branch is never made for a commit evs's ref holds: the rule follows whenever L is E or an ancestor of it (E).

#### 8.2.8 The receive path and the journal

**Hooks.** Each hook file in `<repo>.hooks` execs `ur git-hook <name>`, which dials the daemon's control socket (§5.8's peer-uid check), names the session the daemon set in `UR_GIT_SESSION` when it started `git-receive-pack`, and relays stdin, stdout and stderr. The session id names a session and grants nothing. For pre-receive it also relays `GIT_OBJECT_DIRECTORY` and `GIT_ALTERNATE_OBJECT_DIRECTORIES`, which the daemon gives its git runner for that hook only, after checking that both lie inside the mount's bare repository, so the daemon reads the quarantined objects.

**pre-receive** refuses the whole push, printing why, when any update:

```text
names a ref outside refs/heads/ and refs/tags/
brings a new commit (8.2.3's C, with no import) that fails the committer rule: both config values are printed, and
    `ur evs import` is named when the committer is no client of this sidecar
brings a new commit or tree that is not canonical, a tree past the tree reader's refusals, or a blob over 2 GiB
```

**proc-receive** speaks git's protocol (version 1, no `atomic`), and the daemon answers each update on its own, up to `ReceiveRefCount` at once:

```text
receive(r, old, new):                                  // a shared ref; an owned ref is below
  refuse before any evs write, as `ng <r> <reason>`:   a branch whose short name begins refs/; erasure, ur/index,
        ur/lfs; ur/<id>/... for another sidecar; anything but a deletion of a ref under ur/<this sidecar>/import/
        (`import helper`; 8.2.6), which an owned ref's receive below refuses the same way; an existing tag with
        new not none (`tag exists`); a tag of a non-commit; §11.19's limits; anything but a deletion of a ref
        stopped at a refused version (`ref refused at version <u>`; 8.5)
  P_r, the publish lock, within ReceiveWaitTimeout, else `ng <r> busy`
  L_r:  settle(r); the local ref is not old -> `ng <r> non-fast-forward`; journal update {old, new, RECEIVED};
        read (b, E) from EvsGitRef
  from v1, §11.11's git-lfs tip check, whose refusal deletes the update (`ng <r> lfs objects missing`)
  publish(r, old, new) with the answers of 8.2.5, and:
        tip moved (409, the history does not hold the push)   delete the update; `ng <r> non-fast-forward`
        200, or the history holds the push id                 settled: `ok <r>`; the local update failing (a
                                                              git ref lock): retried to ReceiveWaitTimeout, then
                                                              `ng <r> committed remotely, local update pending`
        unknown at ReceiveWaitTimeout                         `ng <r> remote outcome pending`; the update stays SENT
        waits past ReceiveWaitTimeout with no attempt live    delete the update; `ng <r> busy`
        ReceivePublishTimeout                                 `ng <r> too slow`, nothing sealed (or, sealed, as unknown)
        too large for one push                                `ng <r> too large for one push: ur evs import`
        any other refusal                                     delete the update; `ng <r> <CODE>`
```

`non-fast-forward` is said only when the ref's tip moved and no attempt of the update is in the history, so SEGMENT_GONE, 429 and GATE_CLOSED never read as one, and a commitless version never produces an `ng`.

**An owned ref** (`ur/<this sidecar>/…`) is accepted at once:

```text
receive(r, old, new):   L_r: journal update {old, new, RECEIVED}; git update-ref <r> <new> <old>;
                        it fails (the ref is not old) -> delete the update, `ng <r> non-fast-forward`;
                        the update becomes LOCAL; `ok <r>`
queue(r):               QueueFirstDelay after a LOCAL update, then at most once per QueueInterval, under P_r:
                        E = EvsGitRef.tip, L = the local ref; L = E: nothing;
                        publish(r, E, L): one push for everything queued, FORCE when L does not descend from E
   200                  settle deletes the updates it covers
   tip moved            replay and settle: the rule keeps, follows or conflicts; then again
   a final refusal      (REF_MODE, SCOPE, a limit, VERSIONING): hold {code}: `ur status` shows it and the queue
                        waits for the local ref to move or `ur evs retry`; the commits stay on the local ref
   offline              the queue waits for the connection; at reconnect it builds on the generation then current
   an import's helper   a ref under ur/<this sidecar>/import/ takes no client update but its deletion, refused
                        before the journal (`ng <r> import helper`); a deletion is queued as any other
```

**The journal** is one sealed file per ref with open work:

```proto
message EvsJournalRef {                 // local/<repo>/journal/<ref_id>; never sent
  bytes ref_name = 1;
  repeated EvsJournalUpdate updates = 2;    // oldest first; a shared ref holds at most one
  repeated EvsJournalAttempt attempts = 3;  // every push id sent for them and not yet resolved, oldest first
  uint64 next_seq = 4;
  uint32 hold_code = 5; int64 hold_ms = 6;  // an owned ref's final refusal, or 0
}
message EvsJournalUpdate {
  uint64 seq = 1; bytes old = 2; bytes new = 3;
  uint32 state = 4;                     // 1 RECEIVED, 2 LOCAL, 3 SENT
  uint32 kind = 5;                      // 1 receive, 2 queue, 3 import, 4 conflict
  int64 received_ms = 6;
}
message EvsJournalAttempt {
  bytes push_id = 1; bytes statement_sha256 = 2;
  uint64 base_version = 3; bytes old = 4; bytes new = 5;
  int64 time_ms = 6; bool parts = 7;    // the statement's time, and whether it seals (30 min) or posts (10 min)
}
```

```text
state      written                                          at a start
RECEIVED   before anything else an update does              shared: delete it (nothing was sent and no ref moved)
                                                            owned: the local ref is old -> move it and go LOCAL;
                                                            else delete it
LOCAL      an owned ref's local ref is new                  the queue goes on
SENT       before an attempt's first POST, with its record, resolve(r)
           on every update the attempt covers
(deleted)  the update is applied, refused or dead
```

```text
resolve(r):   replay(r) to the head, from the cluster; then for the attempts, under L_r:
   the history holds an attempt's push id (its statement hash equal; another hash: alarm)
                              -> committed: settle(r) applies it, which deletes the update
   the head's version is above every attempt's base_version, and none is in the history
                              -> dead: TIP lets none of them commit, ever; a shared ref's update is deleted,
                                 an owned ref's goes back to LOCAL
   the head has not moved     -> pending: `ur status` says "remote outcome pending"; ask again at each hint and
                                 each minute; once the local clock is past time_ms + (30 min for parts, else
                                 10 min) + JournalResolveMargin and a head read after that still shows no
                                 attempt -> dead
```

A daemon never sends a statement again after a restart, and never needs to (G): an attempt that is in the history committed, one the head has passed never will, and one that is neither can still land only until its statement's time bound. A wrong "dead" could not move a ref in any case: if a late attempt commits after all, it is a version like any other, and replay applies it.

#### 8.2.9 Locks, and the order of fences

```text
P_r   the publish lock of ref r (per mount, in memory): held by whoever builds and sends a push for r, across
      the network: a receive, the queue, an import, the mapper's PATH_EPOCH and a local rekey; it makes one
      device's pushes to one ref take turns, so the second of two sibling pushes answers from the local ref
L_r   the apply lock of ref r (EvsRefLocks, as landed): held for local state only: EvsGitRef, the journal file,
      the tips log and `git update-ref`; never across a request to evs or a wait
M     the mount's upkeep lock: shared by every receive session, replay flush and publish; exclusive for git gc
order M (shared), then P_r, then L_r; L_r is never held while taking P_r or waiting on evs;
      two refs' locks are never held together: a transaction touches one ref
sync  takes L_r only, so it never waits on a push, and a push never waits on sync but for one local write
```

Each line below is the order in which one actor meets its fences, and a later one never stands in for an earlier.

```text
a git push     pre-receive (quarantine): ref namespace, new commits' committers and forms
               proc-receive: name rules; P_r; L_r {settle, local ref = old, journal RECEIVED, read (b, E)}
               publish: build; journal SENT {push id}; lease; parts; seal
               evs: 5c the refs table; 5d the gate; 5e the epoch; 5f TIP and the lease; 5g; 5h; step 7
               the answer or the history; L_r {EvsGitRef, update-ref old -> new, applied_tip, journal}; ok
an owned ref   L_r {journal RECEIVED, update-ref old -> new, journal LOCAL}; ok; then the queue as a git push
sync           the verifier's walk; check(u); the sink's flush; L_r {EvsGitRef, settle}
a restart      stale git lock files removed; journals read; RECEIVED settled as 8.2.8's table; settle(r) for each
               ref whose applied_tip is not its tip; resolve(r) for each SENT; then listeners open
```

#### 8.2.10 Path epochs, rekeys and the name index

**PATH_EPOCH.** A git-mode ref's PATH_EPOCH push is section 9's, on the tip, under P_r when this device maps. It carries no `git` and moves no tip. A waiting git push that loses TIP to one is retokened (8.2.5). Tag refs have no entries, so no token, no due and no map: evs records a due only at a commit, and an IMMUTABLE ref takes none.

**A new ref's path epoch** (question evs1-m2-44-new-ref-crossing, option 2; QD-632). The push that creates a ref names the epoch the ref starts in, by section 9's rule (9.2.3), and evs holds it to that (9.2.6). A branch with no base, and a tag ref, which sends no token, name the newest REMOVE generation the creating device holds, 1 when there is none. An overlay names its base ref's current epoch, read from the base ref's head within `EpochFreshFor` as `PlanGitUpdate` reads the new ref's absent one: overlay and base then share every token path, an inherited name's floor on the overlay is its floor on the base (8.2.4), and a held directory's first table sends no token the base has not shown. Each ref cuts over by its own PATH_EPOCH afterwards. While the base ref is under an immediate removal, a creating push that holds any change waits as on 412 PATH_EPOCH_DUE, within its caller's wait bound: an agent's new branch, a conflict branch, which stays local and listed until its queue can publish it, and an import's helper that is an overlay. A branch or tag at a commit a ref already reaches is an empty push, creates no path and does not wait.

**The replayed name index.** For each mounted git-mode branch the local tier registers section 9's `EvsNameIndex` (EVS1-M2-47's seam):

```text
Head           the ref's EvsGitRef: version, chain, and the epoch state replay recorded
Walk           a branch with no base: the root, then `git ls-tree -r -t -z <tip>`, a directory before what it holds
               an overlay: its held set's standing paths, in the same order; an inherited path is the base ref's
born           the born journal: replay notes, for each path a version created after the cut-over that listed the
               oldest standing source, the epoch of that version; a removal drops the path and what is below it;
               the journal empties when the sources drop
CreatedAfter   for each version in (S, Head], from the tips log: the paths of tree(tip_u) that tree(tip_(u-1)) lacks,
               by the tree reader, and on an overlay the paths that version first held
```

**Rekey** (question keys-m2-26-rekey-git-mode-refs, option 1). A rekey of a git-mode ref is the REKEY shape: an ordinary push on the tip whose changes re-checkpoint files under the current generation and change no mode, oid or name. Any writer's device can send it, a head-mode one included, since it needs no tree: `EvsRepo.WritePaths` takes a git-mode ref when every write has `ForceCheckpoint` and `IfVersion` and no `Remove`, the planner refuses a write whose new blob's oid is not the standing version's (`ErrEvsGitRef`, as today, for anything else), and the sender seals `git {shape: REKEY}`. evs needs no rule: TIP, 5g and 5h hold it as they hold any push, and a replaying reader holds each entry to the tree (8.2.7). KEYS-M2-26's job then walks a git-mode ref as it walks a file-mode one. It covers the ref's own entries: an overlay's held files, and nothing on a tag ref. History blobs and sealed commits are never rekeyed, as a file-mode ref's older versions are not. On a device that mounts the repo, `WritePaths` takes P_r for a git-mode ref, so a rekey and a git push from one device do not race each other to the tip.

#### 8.2.11 The bare repository's upkeep

`EvsMounts.Add` sets, beside what it sets today: `transfer.hideRefs refs/ur`, `gc.auto 0`, `receive.autogc false`, `transfer.fsckObjects false`, `receive.denyNonFastForwards false`, `receive.denyDeletes false`, `core.logAllRefUpdates false`. Force and delete are evs's to judge, by §11.8's table. The daemon runs `git gc --quiet --prune=2.weeks.ago` itself, holding M exclusively, at most once per `GcMinInterval`, when `git count-objects -v` shows over 2,000 loose objects or 50 packs. What must outlive a prune is reachable: evs's tips through `refs/ur/evs/`, queued commits through their local refs, conflict branches, an import's source through `refs/ur/import/`. What is not, the objects of a push that was refused or of a replay that stopped, is younger than two weeks or is fetched again. At a start, with no git child alive, the daemon deletes every `*.lock` under the bare repository's `refs/` and its `packed-refs.lock`; while running, a lock older than `GitCommandTimeout` plus a minute is deleted before a retry.

### 8.3 Invariants and why they hold

**G1, exact oids.** Every commit, tree, blob and tag a ref's tip reaches is rebuilt by every replaying reader with its original oid. *Why.* A commit, an annotated tag and a raw tree arrive as their bytes and are hashed before they are used. Every other tree is `EvsGitTree.Encode` of entries the reader derives from its first parent's tree and the commit's changes, which is the function that decided the tree was canonical when the push was built, and the result must equal the oid the commit's bytes name; a wrong change, a missing raw tree or a raw tree whose reading differs from the built entries fails there. A blob's oid is checked when its record or chain is opened. `git index-pack` hashes every object once more as it stores it. By induction over the carried order, the first parent's tree is right when a commit's is built.

**G2, closure.** When a version is applied, the reader's object store holds everything its tip reaches. *Why.* C is what the tip reaches outside old, the base tip and the sources' tips, and B likewise for blobs (8.2.3). The reader holds what old reaches by induction over the ref's versions, what the base tip reaches by induction over the base ref, and what a source's tip reaches because `check` replays the source to that version first. Each carried commit is checked to have parents held or carried, each blob to be held or carried, and the tip to be the top of the carried commits, so a push that leaves anything out is refused, not applied. The sink is flushed before `EvsGitRef` moves, so a crash never leaves a ref ahead of its objects.

**G3, the forced identity is a property of the stored history (owner decision 81).** Every commit any ref's history holds was, at the first push that carried it, either its signer's own, by the decided rule, or one of the commits an `EvsImport` a repo admin signed for that push lists. *Why.* A carried commit is checked one way or the other in `check`. A commit that is not carried is held from old, a base or a source, each of which is an earlier version of some ref. "Earlier" is well founded: a version is applied only after every version it names, and a cycle of waits is refused, so following where a commit came from ends at the push that carried it. A writer cannot borrow an admin's `EvsImport`: its hash is over the carrying push's own commit list. `GitSync` does not model this; the argument is the induction.

**G4, the path state is the tip's tree.** After every applied version of a branch, evs's entries describe tree(peel(tip)): directly, or for an overlay through 8.2.4's reading. So a head-mode reader of a ref and a git user of its tip see the same files. *Why.* `check` holds an UPDATE's changes to exactly the net change between the state before and the new tip's tree, entry by entry, a REKEY's to no change of mode or oid, and a PATH_EPOCH has none. A DELETE leaves the entries, and the next UPDATE's net change starts from the tree they describe. On an overlay a held directory's table lists exactly the new tree's children, by the same check, so "absent from a held table" is absent from the tree, with or without a marker. A head-mode device cannot run `check`. It trusts that a replaying reader would have alarmed, which is §11.9's trusts row as it stands.

**G5, one update, one version.** A push id commits at most once, and no version repeats the update before it. *Why.* evs's 5a and TIP. A daemon builds a second attempt for an update only on a base above every earlier attempt's, or on the same base once evs has refused the earlier one for good or its time bound has passed, and two attempts on one base cannot both pass TIP in any case. An attempt that committed is in the history the second is built from, and then the update is done and nothing is built. Model: `NoDuplicate`.

**G6, no acknowledged commit is lost.** A commit the daemon answered `ok` for is in a tip evs committed, or still on its local ref, or on a conflict branch of that device, unless the client's own forced update dropped it. *Why.* A shared ref is answered after evs's commit is in the history and applied. An owned ref's commit is on the local ref from the `update-ref` that precedes its `ok`, and the only things that move a local ref afterwards are a client's update, and settle, which follows only when evs's tip holds the local commit and otherwise keeps it or puts it on a conflict branch in the same git transaction that moves the ref. Model: `AckedDurable`, `SharedSafe`; `GitSyncTwin-NoApplyLock` loses a commit as soon as settle's read and write are not one step.

**G7, truthful answers (FI-9).** `ok` is said only of an update that committed and whose local ref has moved. `non-fast-forward` is said only of an update none of whose attempts ever commits. Everything else is a `ng` that promises nothing. *Why.* `ok` needs the push id in the history. `non-fast-forward` needs the head above every attempt's base with none of them in the history, and TIP then refuses each for good. Model: `TruthfulNg`; the twins `NgOnUnknown` and `NoRecognition`.

**G8, a local ref shows only what evs committed.** A shared ref's local ref is the tip it was last settled to or the tip the mirror holds; an owned ref's is that, or ahead of it by its own queue. *Why.* Only settle and an owned ref's receive call `update-ref`, both under L_r. Model: `SharedSafe`, `MirrorExact`; `GitSyncTwin-BlindUpdateRef` breaks it with the `update-ref <new> <old>` the journal row describes, run after sync has passed the push.

**G9, conflicts are real, and devices converge.** A conflict branch is made only for a local commit evs's ref does not hold. When every device has applied the whole history, no entry is open and nothing can still land or be sent, every local ref is evs's tip. *Why.* Settle follows whenever the local ref is evs's tip or an ancestor of it, before it considers a conflict. After a settle the local ref is evs's tip, or ahead of it with a queue that can send. Model: `NoSpurious`, `Converge`; the twins `EqualsOld` and `RefusedDropOnly`.

**G10, descent, FORCE, DELETE and IMMUTABLE follow §11.8's table.** *Why.* evs holds FORCE and DELETE to scope and ref kind at 5c and an IMMUTABLE ref to DELETE alone. Descent is the reader's: an UPDATE without FORCE whose old tip is not an ancestor of its new one is refused by `check`, so a writer cannot rewrite history by leaving the flag off, and one that sets it needs the scope evs enforces and readers check again from the access log (`evsCheckRefRules`).

**G11, no GC takes what a git-mode push introduced.** A history segment is named by no entry version, and it stays while its push is retained. *Why.* Orphan GC deletes only a segment no committed push introduced, and "introduced" is the push's new-objects list as pidx/ keeps it (section 2.2). Marker collection and the purge delete kind-5 segments and slots of versionless versions, which a git-mode ref never has. A DROP is refused on git-mode refs. One thing must be held to by code not yet written: D-EVS-64's drop job "marks every ref's live versions", and evs-4's row deletes "a kind-1 segment that only executed drops' listed versions name". A history segment is named by no version at all, so a job that swept every unmarked segment of a repo would take it at the repo's first drop. The job's candidates must be the segments its listed versions' chains name and nothing else. 8.8 gives §11.13 and evs-4 that sentence, and EVS2's drop tasks (M10) must build to it.

**G12, bounded cost.** A push's bytes, reads and memory are bounded by what it changes and carries (8.4).

**Helper refs add no rule to these** (QD-604). A helper is a branch, its pushes are import pushes and its end is a DELETE, each of which G1 to G11 already cover; the step's push that names it is G2's and G3's source case. Two things they rest on are worth saying. G2 and G3 need a named source version to stay replayable after its ref is deleted: it does, since a DELETE is a later version of the same history and evs retains a ref's versions and what their pushes introduced (G11), which is also what lets any merged and deleted branch stay a source. And G3's induction is unchanged: a commit the merge step does not carry was carried by a helper's push under that push's own `EvsImport`, signed by a repo admin for the helper's ref id.

**The model.** `GitSync.tla` is one git-mode ref on evs and each device's side of it. A commit is the set of the history it holds, so ancestry is inclusion. A push attempt, once sent, may reach evs at any step, any number of times, until its time bound drops it, and a daemon learns an outcome only from the ref's history, which is the worst case of every lost answer, lb re-send and stalled write. Daemons crash and restart. `LocalFirst` chooses a shared ref or an owned one; two devices on an owned ref are one sidecar's state restored or copied, the way an owned ref diverges. Its invariants are `MirrorExact`, `NoDuplicate`, `AckedDurable`, `SharedSafe`, `TruthfulNg`, `NoSpurious` and `Converge`, read above.

Left out, and why it is safe. What a push carries and how a reader checks it change no ref's value: a refused version stops a ref where it is (8.5). An import's helper refs change neither the journal nor a sync fence, so the model is not extended for them (QD-604): each helper is one more ref moved only by publish under its own P_r and by settle under its own L_r, its pushes are journaled as an import's (kind 3) and resolved from its own history, the import holds one publish lock at a time, and the receive path's refusal of a client's update there is a name rule ahead of every fence. What a kill leaves is the import record's to resume (8.2.6), not the journal's. Parts, leases and every refusal but TIP's end as "the attempt never commits", which `EvsDrop` is. Several clients on one device are serialized by P_r. A ref moved outside the daemon is 8.2.7's rule on inputs the model never produces. Liveness beyond `Converge` is not checked: a queue that evs keeps refusing is a hold a person clears.

The runs, on TLC from the owner's jar (master at `d8fb231`), through `run-gitsync.sh`:

```text
configuration                          what it holds, and the result               distinct states   depth        time     disk
GitSync.tla, the design (Twin none)
GitSync                                a shared ref, 2 devices, 3 pushes, 4 versions, 1 crash, 1 commitless version
                                       pass, every invariant                             3,611,441      35  1 min 54 s   237 MB
GitSync-Force                          a shared ref whose clients may force, 2 devices, 3 pushes, 4 versions, 1 crash
                                       pass, every invariant                               485,286      30         9 s    78 MB
GitSync-Crash                          a shared ref, 2 devices, 2 pushes, 3 versions, 2 crashes, 1 commitless version
                                       pass, every invariant                               165,468      27        11 s    22 MB
GitSync-Owned                          an owned ref on two copies of one sidecar, 3 pushes, 4 versions, 1 crash, 1 commitless
                                       pass, every invariant                             3,546,934      34        40 s   240 MB
GitSync-OwnedForce                     the same, clients may force, no commitless version
                                       pass, every invariant                             1,178,770      33         9 s   106 MB
GitSync-Three                          a shared ref, 3 devices, 3 pushes, 3 versions, 1 crash, 1 commitless version
                                       pass, every invariant                            18,830,900      34  7 min 10 s   705 MB
GitSync-Wide                           a shared ref, 3 devices, 5 pushes, 7 versions, 2 crashes, 2 commitless, force; by simulation:
                                       2,800,000 traces (200,000 a worker, 14 workers) of at most 60 steps from seed 8
                                       pass, every invariant                 142,967,253 generated      60  3 min 54 s     0 MB
GitSync-WideOwned                      an owned ref on three copies, the same bounds; by simulation, the same traces
                                       pass, every invariant                 160,931,893 generated      60   6 min 6 s     0 MB
GitSync.tla, one rule of the design broken
GitSyncTwin-EqualsOld                  §11.11's restart row as written: a committed entry whose local ref is not old (E)
                                       NoSpurious violated, a trace of 7 states                593       9         0 s     0 MB
GitSyncTwin-BlindUpdateRef             the hook's update-ref <new> after evs's 200, whatever sync applied since (F)
                                       SharedSafe violated, a trace of 12 states             1,805      14         0 s     0 MB
GitSyncTwin-NoApplyLock                settle's read and write of the local ref are two steps around a receive (F)
                                       AckedDurable violated, a trace of 10 states             830      12         0 s     0 MB
GitSyncTwin-NgOnUnknown                an unknown outcome answered as a non-fast-forward (G)
                                       TruthfulNg violated, a trace of 5 states                 27       9         0 s     0 MB
GitSyncTwin-NoRecognition              the daemon takes its own committed push for another's commit (G)
                                       TruthfulNg violated, a trace of 7 states                 27       9         0 s     0 MB
GitSyncTwin-RefusedDropOnly            a queued update evs can never take is dropped and the local ref left (M)
                                       Converge violated, a trace of 11 states               1,308      13         0 s     0 MB
GitSync.tla, the design, with a state it must reach denied
GitSyncReach-Conflict                  "no conflict branch is ever made" must fail on an owned ref that diverges
                                       NoConflict violated, a trace of 9 states                599      12         0 s     0 MB
GitSyncReach-Reconcile                 "no update whose answer a crash lost is found committed and applied" must fail
                                       NeverReconciled violated, a trace of 8 states            740       9         1 s     0 MB
GitSyncReach-Resign                    "no update commits on its second attempt" must fail after a commitless version
                                       NeverResigned violated, a trace of 11 states            127      13         0 s     0 MB
```

Every design run that reports distinct states is the complete graph at its bounds. The two Wide runs are simulation, and show only that the behaviors they drew kept every invariant. A twin or reach run stops at the first trace its workers find, so its trace and its counts vary by a state or two between runs. Disk is the most a run's state directory held; each was deleted when its run ended.

Each named counterexample is gone from the design and present in its twin: E is `GitSyncTwin-EqualsOld` (`NoSpurious`), F's second half is `GitSyncTwin-BlindUpdateRef` (`SharedSafe`) and `GitSyncTwin-NoApplyLock` (`AckedDurable`), G is `GitSyncTwin-NgOnUnknown` and `GitSyncTwin-NoRecognition` (`TruthfulNg`), M is `GitSyncTwin-RefusedDropOnly` (`Converge`). The three reach configurations show the design gets to the states the scenarios need: a conflict branch after a real divergence, a crash between evs's commit and the local update reconciled from the history, and a push signed again after a commitless version.

One thing the model found in the design as first written: on an owned ref a client's forced update drops the queued commit before it, which had been answered `ok` and never reached evs. That is stock git's meaning of a forced push and stays; G6 says so, and the queue's one push per ref makes it explicit that evs sees a queue's last state, not each step.

### 8.4 Cost

Assumptions, each a round number for a concrete case. A sealed commit is its object (300 B) and its changes (85 B a path: four names of 12 B, a mode and an oid). A file entry version is 450 B and a directory row 110 B. A history blob's sealed record entry is 80 B. A record's header is 160 B. evs's own cost for a push is §11.8's: three store round trips of 40 to 80 ms, three for each part, four for a seal, one for a lease.

```text
case                              sealed metadata     entries              content uploaded        parts   evs reads
an agent's commit: 1 commit,      0.8 KiB             5 x 450 B            5 diffs, 20 KiB, inline    1    1
  5 files changed                                                          or one segment
an agent merges main into its     the merge commit:   120 x 450 B = 54 KiB none where main's entry    1    2 on the
  branch: 40 commits by others,   120 x 85 B = 10 KiB                      holds the blob (reuse)          ref, 2 on
  120 files                       1 source                                                                main
the same without sources          + 40 commits, 23 KiB                     + their blobs              1
  (the design as written)         and replay refuses them (8.1 C)
2,000 commits, 30 files           1.1 MiB             30 x 450 B           about 6,000 history         2    1
                                                                           diffs, 10 MiB, 2 segments
a 100,000-file commit on a        8.1 MiB (its        106,000 entries,     1.2 GiB, 150 segments     104   none (a
  new ref (§22.8's pushes row)    changes)            53 MiB                                               new ref)
a branch or tag at a commit a     about 100 B         none                 none                        1    none
  ref already reaches
```

A push of at most 64 KiB is one upload at most and one POST, inside §11.15's "local push to remote commit, p50 at most 1 s": the local work is one `rev-list`, the tree reads of the changed paths (5 paths at depth 4 are 40 trees) and one read of evs. On device B it is one push read, the fetch of what it carries, one `index-pack` and one `update-ref`, inside "visible on device B, p50 at most 2 s". Drive writes at evs are §11.13's per push and are not changed by anything here: a history segment is one more segment, and a changeless part one more part.

**A large import.** 1,000,000 commits, three paths changed in each, 150,000 paths ever and 100,000 at the tip, a mean blob of 12 KiB and a mean diff of 1.5 KiB:

```text
sealed commits        1,000,000 x 570 B                                   0.53 GiB
history blob entries  2,900,000 x 80 B                                    0.22 GiB    all sealed metadata: 0.75 GiB
entries               100,000 files and 6,000 directories                 53 MiB
history content       150,000 first versions x 12.2 KiB, 2,750,000 diffs x 1.7 KiB    6.0 GiB
entry content         100,000 checkpoints x 12.2 KiB                      1.1 GiB     with Padmé's 3%: 7.4 GiB,
                                                                                      950 segments of 8 MiB
parts                 about 820 of 1 MiB if it were one push
pushes                2 at 20 Mbit/s (ImportPushPartCount); 3 at 5 Mbit/s (ImportPostTime: 10 min x 0.6 MiB/s)
upload                segments 53 min at 20 Mbit/s and 3.5 h at 5 Mbit/s, 4 at once, each receipt used well inside
                      22 h because a push seals what it uploaded; parts 6 min and 23 min in all
local work            24 M tree reads and 65 GiB of blob bytes through git cat-file, 2.75 M deltas, 7.4 GiB sealed:
                      an estimate of 20 min of one core
memory                the tree cache (64 MiB), four segments being filled (32 MiB), one commit's changes, the spool
                      on disk; nothing per commit or per path
evs                   entry folds for about 100,000 to 300,000 paths in all (each cut's net change), not 3,000,000
```

The same history in git's own pack is about a tenth of that: evs seals records uncompressed (§11.6), so its bytes are the diffs' and the first versions' plaintext. That ratio is format 1's and not this section's to change.

On the reading side a device's first sync of that ref fetches the same 8.2 GiB, rebuilds about ten trees a commit, and writes undeltified packs: by estimate 13 GiB in the bare repository before its first `git gc` and 2 GiB after. Its memory is the same three bounds.

A push's hard limits, checked before anything is sent: 1,024 parts; 1,048,576 entry writes; 16 sources; §11.19's directory bounds on the tip's tree. A history with one first-parent step past a push's bounds, about a million commits merged at once, is imported through a helper ref the import makes for the merged side (8.2.6; QD-604).

**A step through a helper.** The case above with a second history of the same size merged into it at the tip: 1,000,000 commits on the merged side, 100,000 files at its tip, none shared with dst.

```text
the side, into its helper   as the large import above: 2 or 3 pushes, 0.75 GiB of sealed metadata, 7.4 GiB of
                            segments; the helper has no base, so its last push leaves the side's tip tree as
                            entries: 53 MiB and 106,000 idx entries
the merge step on dst       1 commit; the net change of dst's tree: 100,000 files the side brings, each entry
                            citing the helper's standing chain (8.2.4's reuse), so 45 MiB of entries in about
                            45 parts and no content uploaded again; 1 source
cleanup                     1 DELETE push, about 100 B
extra over one ref          the helper's 53 MiB of entries, which stand after the DELETE until the repo is
                            shredded; one more ref for each reader to replay, the same bytes in all
local                       own(q) is one rev-list --count per other parent of an oversized step; the record is
                            under 200 B a helper
```

A helper that is an overlay of the branch its side forked from holds only the paths that differ, as any overlay does. An import with no oversized step makes no helper and costs what it did.

### 8.5 Failure modes and recovery

```text
the daemon dies ...                           what is on disk                 at the next start
before the journal's RECEIVED                 nothing                         nothing; git reported a broken push
after RECEIVED, before anything is sent       RECEIVED                        shared: deleted. owned: the local ref is
                                                                              moved if it is still old, as the push asked
after SENT, before the POST arrives           SENT {P}                        resolve: the head has not moved; pending
                                                                              until P's time bound, then dead
after evs's commit, before update-ref         SENT {P}                        resolve: P is in the history; settle moves
                                                                              the local ref (FS-5's kill case)
between EvsGitRef's write and update-ref      tip != applied_tip              settle runs again on the same inputs
between update-ref and applied_tip            the same                        settle finds L = E and records it
mid replay                                    objects in a pack or lost       the versions are replayed again; objects
                                                                              are content-addressed
mid import                                    the arguments; the ref at a cut the command resumes from the ref's tip
mid import, inside a helper                   the record's helper, open; the  the rerun finds the helper by its (merge,
                                              helper ref at a cut             parent) pair and goes on from its tip
after a helper's record entry, before its     an entry with no ref            the rerun's first push creates the ref
  first push
after the helpers, before the merge step      helpers done; dst at c_(j-1)    the step is no longer oversized: its push
                                                                              names the helpers as sources
mid cleanup                                   some helpers deleted            the rerun deletes the rest, skipping a ref
                                                                              evs shows deleted, then the record
mid upload of a large push                    segments at evs, unadopted      shared: nothing; section 2's orphan GC
                                                                              takes them. owned: the queue builds again
```

```text
what goes wrong                               what happens
an answer is lost, or the lb re-sends         the same statement again while the process lives; then the history
two devices push siblings                     one commits; the other reads the history, finds the tip moved and its
                                              push absent, and answers non-fast-forward: stock git's fetch-and-merge
two pushes to one ref on one device           P_r: the second waits, then finds the local ref is not its old
sync applies a push before its 200 is read    the 200's replay finds the version applied; ok
a PATH_EPOCH lands under a waiting push       retoken on the new base; no ng (FS-5)
a rekey lands under a waiting push            built again from step 3; no ng
GATE_CLOSED, 429, PATH_EPOCH_DUE, a lease     waits within ReceiveWaitTimeout, then `ng <ref> busy`: never non-fast-forward
SEGMENT_GONE, SEGMENT_STALE                   re-uploaded, a new push id
a git ref lock is stuck                       retried; a lock older than GitCommandTimeout + 1 min removed; the push is
                                              committed and says so (`committed remotely, local update pending`)
evs's ref was forced by an admin              settle follows: the local ref is the applied tip, so nothing local is lost
evs's ref was re-seeded below the version     not a version applied in order: once the verifier accepts the EvsReseed
  this device applied (§19.10)                (EVSB-M2-20), EvsGitRef is set to the re-seeded head with applied_tip none,
                                              so settle follows only a local ref that is an ancestor of the new tip and
                                              otherwise makes a conflict branch: what the incident lost and this device
                                              still holds is kept, and can be pushed again
an owned ref diverged (restored state)        a conflict branch, published; evs_conflict; the local ref follows evs
the queue's push is refused for good          a hold with the code; `ur status`; the commits stay on the local ref
a source ref cannot be replayed               the dependent ref waits (`waiting_source` in `ur status`), no alarm on it
an import step is oversized                   the import makes a helper ref for the largest merged side and repeats
                                              until the step fits (8.2.6); nothing of the step is sent before it does
a helper's push is refused for good           the import stops, naming the helper ref, the code and the commit; dst is at
  (SCOPE, REF_MODE, a limit)                  the cut before the step; the record and the helpers stay; a rerun resumes,
                                              and `ur evs import --abandon` deletes the helpers and the record
a helper's push waits (GATE_CLOSED, 429,      as any import push: waits and retries; a helper that is an overlay of a
  PATH_EPOCH_DUE)                             ref under an immediate removal waits for that ref's cut-over (8.2.10)
a step needs over 16 sources, 64 helpers      the import stops before any write for the step, naming the commit and the
  or 8 levels, or one commit changes over     bound; what it imported stays, and its helpers stay until a rerun
  1,048,576 entries                           finishes or `--abandon`
a helper ref is deleted while its import      the rerun marks it abandoned and makes another under the next number; the
  runs                                        deleted one's history still serves any push that named it
a helper's cleanup DELETE fails               the import ends with dst at the source tip and says which helpers are
                                              left; a rerun, or `--abandon`, deletes them
a client pushes to a helper ref               `ng <ref> import helper`; only its deletion is taken
the import record is lost with local/<repo>/  helpers no record names: `ur status` lists them as leftover; a new import
                                              makes its own and carries only what their tips do not hold
a helper is deleted, and a device first       the merge step names (helper, version): replay reads the helper's versions
  syncs dst afterwards                        below its DELETE as before it (8.2.6's cleanup)
a version fails check                         evs_alarm; the ref stops at the version before; its local ref is left
                                              alone and still serves; receive answers `ng <ref> ref refused at version u`
the bare repository is lost or corrupt        `ur mount add` again: replay rebuilds it from evs; queued commits that
                                              were only there are lost with it, as with any local git repository
local/<repo>/ is lost, the repository kept    replay from version 1 recomputes it; local refs equal to evs's tips are
                                              followed, and any other becomes a conflict branch
```

A ref that stops at a refused version u stays stopped until the ref is deleted on evs. A DELETE at a version w above u carries nothing to check, so a stopped reader skips to w, applies it (its local ref is its applied tip, so it is deleted) and replays on. A stopped device's own receive path takes that deletion and nothing else for the ref, and builds it on the head's version with no old tip. The versions in between wrote entries no reader vouches for, so every token path their change lists name, which are cleartext, is *tainted* in the reader's `EvsGitRef`. The push that re-creates the ref must write or remove each tainted token path beside its net change against the last tree applied, which its sender can do without the names: a removal needs the token path, its standing version from a read, and the parent's `removed_tokens`. `check` holds it to that, and the taints clear. Recovery from a forged or broken push is therefore `git push --delete` and a new push, by an admin on a shared ref and by its sidecar on an owned one. The refused versions stay in evs's history; export reports them and goes on from the DELETE.

### 8.6 The test plan

Every test is deterministic: a fake clock, barriers at `evs.local.<point>` (publish.sent, publish.answer, apply.state, apply.ref, apply.done, queue.send, receive.local), a stand-in evs or `evsservice` on `FakeBlobs`, and real stock git on a temporary bare repository.

**The codec and the builder (`evs_git_object_test.go`, `evs_git_tree_test.go`; EVS1-M2-49).** Vectors, each made by stock git and checked against its oid: a tree with a zero-padded mode, with mode 100600, out of order; a commit with a late `committer`, with a NUL in a header, with no blank line; an annotated tag, a tag of a tag. The tree reader refuses a name with a slash and a repeated name. The builder: 1,000 random commits from go-git's oracle rebuilt with equal tree oids from changes alone; a raw tree inherited across a commit that changes a sibling directory; a raw tree whose reading differs from the changes, refused; memory flat over 100,000 commits (the cache's bound asserted). A fuzz target for the tree reader and one for the graph decoder, registered in `check/`'s fuzz registry.

**Git to evs (`evs_local_publish_test.go`; EVS1-M2-34).** A's scenario: two commits, one push, the middle blob a history blob, and a second device's `git fsck --strict` clean. A file added and removed inside a push. A 2,000-commit push in two parts, the second changeless. A branch at an existing commit, a lightweight tag and an annotated tag: one empty push each, the tag IMMUTABLE, a second push to it refused. A forced rewind. A DELETE and a re-creation whose net change starts from the old tree. C's scenario: a pull of two other sidecars' commits names one source and carries only the merge; with 17 branches merged at once the 17th's commits are carried. A rename keeps the file_id and uploads nothing; a merged file is cited from its source ref, and a moved-on source falls back to a checkpoint. FS-5's overlay cases, and H's: an inherited file removed, its directory then held whole, the removal standing after a marker collection and after a path-epoch copy; a file changed in a directory the overlay never holds. N's: a file replaced by a directory and back; a gitlink. §11.19's limits refused before any evs write. An import: a foreign history of 10,000 commits in three pushes by a lowered `ImportPushPartCount`, each `EvsImport` checked alone; a writer's push carrying the admin's `EvsImport` with other commits, refused by replay; a kill between pushes and a rerun; a history with raw trees and late headers, its export's oids equal; a tree name with a slash, refused naming the tree; a 100,000-file commit as one multi-part push (§22.8's row), run at 1,100 files in the unit leg. Helper refs (QD-604), each with `ImportStepPartCount` lowered so that a side of a few hundred commits is oversized: a merge of two disjoint histories imports through one helper, `ur/<sidecar_id>/import/<id>/1`, the merge step's push carrying the merge commit alone and naming the helper's version as its one source, each push's `EvsImport` checked alone, and a second device's `git fsck --strict` clean; a side that itself merges an oversized side makes a helper inside a helper, numbered in the order first needed; an octopus merge of three sides of which two are oversized makes two helpers and carries the third; a side that forked from dst's line gets a helper that is an overlay; after the import every helper is deleted on evs, no `refs/heads/ur/<sidecar_id>/import/` is left on either device, `refs/ur/evs/` keeps each last tip, and a third device that first syncs dst then replays each deleted helper to its named version and ends with equal oids; a kill at each of `evs.local.import.helper_recorded`, `.helper_pushed`, `.helper_done`, `.step_sent` and `.clean_deleted`, each rerun finishing with the same refs and no second helper for a pair; a helper deleted mid-import, abandoned and replaced; a helper push refused SCOPE stopping the import with dst at the cut before the step, and `--abandon` deleting the helpers and the record; a step past `ImportHelperCount`, past `ImportHelperDepth`, and one needing 17 sources, each refused before any evs write for the step, naming the commit; an import with no oversized step making no helper.

**Evs to git (`evs_local_sync_test.go`; EVS1-M2-35).** A push on device A applied on device B with equal oids and a clean `git fsck`. Each line of `check` broken in turn by a hand-built push, each refused with its alarm and the ref left: a forged committer; a commit of another sidecar carried without a source; a source that does not reach it; a missing history blob; a change that is not the tree's; an UPDATE that does not descend, without FORCE; a REKEY that changes an oid; a second push to a tag. A committed FORCE and a git-mode PATH_EPOCH raise no alarm (FS-1's case). A source ref replayed first, a missing source leaving the ref waiting, a cycle refused. A stopped ref resuming at a DELETE, its re-creating push refused until it writes or removes every tainted token path. Settle's table, one test a row, with a kill at each of `apply.state`, `apply.ref` and `apply.done`. Conflicts: an owned ref with two copies of one sidecar; the conflict branch published and visible on a third device; the 65th conflict stopping the ref; no conflict for E's schedule. Sync racing a receive on one ref at every barrier order (the seeded explorer, 10 seeds a merge). The replayed name index against `sidecartest.FakeNameIndex` for one tree, an overlay included.

**The receive path (`evs_local_receive_test.go`; EVS1-M2-36).** FS-5's journal cases with stock git as the client: two clients push siblings and the second gets `! [remote rejected] … (non-fast-forward)`; a push whose head moved only by a PATH_EPOCH, and one by a rekey, land with no `ng`; SEGMENT_GONE, 429 and GATE_CLOSED never read as non-fast-forward; a two-ref push reports each status; `git push --atomic` fails before any write; the daemon killed at each row of 8.5's first table; a git ref lock held after pre-receive. G's: an unknown outcome answered `remote outcome pending` and later resolved each way, with no statement sent twice across the restart. An owned ref: `ok` before evs, three pushes coalesced into one, a forced local update, an offline queue re-sealed at the generation current at reconnect, a final refusal held and released by `ur evs retry`. pre-receive: a foreign committer refused with both config values, a non-canonical new commit refused, a ref outside refs/heads and refs/tags refused, the quarantine paths checked to lie in the bare repository. An import's helper ref: a client's push to it answers `ng … import helper`, and its deletion is taken.

**Model twins in code (`sidecartest/evs_git_twins_test.go`, a new file of EVS1-M2-43).** One schedule per twin of 8.3, run against the real code, which must hold where the twin breaks: `EqualsOld`, `BlindUpdateRef`, `NgOnUnknown`, `NoRecognition`, `NoApplyLock`, `RefusedDropOnly`.

**The client matrix (§22.9's git row; EVS1-M2-43).** Through the local tier, and `git-remote-ur` with no prior mount, for stock git 2.34, 2.43 and the latest, on Linux, macOS (Xcode's) and Windows, and for go-git, JGit and libgit2 as clients over http and OpenSSH:

```text
every client     clone, fetch, push; oids equal a reference repository; a sibling push refused, the client's
                 report holding the daemon's `non-fast-forward`; a two-ref push with one ng; an annotated tag; a
                 branch delete; refs/ur/ not advertised
stock git        push --atomic fails before any write; push --force by an admin and by a writer (refused, SCOPE);
                 the kill between the remote commit and update-ref; a foreign commit refused, an import accepted
2.34             receive.procReceiveRefs and receive.advertiseAtomic behave as on the latest; committer.name and
                 committer.email are honored
go-git, JGit,    as clients over http and OpenSSH: every row of "every client"
libgit2
```

**Twenty agents (§22.8; EVS1-M2-43).** As planned, and it now also asserts: a merge into `main` of commits already on evs names their refs as sources and carries none of them, and no push carries another sidecar's commit; no conflict branch; `git fsck --strict` on a second device; export's oids equal.

### 8.7 Implementation notes, task by task

Two new tasks change landed code before the held ones can pass their tests. `.stack/plan/proposals/details-8-tasks.md` gives them and the three changed entries in the plan's format. All are the data lane's.

**New: EVS1-M2-48, git-mode pushes on the wire and on evs** (sidecar; M). 8.2.2's fields and rules.
- `protocol/evs.proto`, `evs.pb.go`, `protocol/EVS-FORMAT.md`, `testdata/evs/` vectors, `protocol/evs_descriptor_test.go`: `EvsGitUpdate`, `EvsGitShape`, `EvsSealedBlob`, `EvsHistoryLocator`, `EvsSealedTree`, the three new `EvsSealedMetadata` fields, `EvsSealedCommit.trees`, payload sections 15 and 16, and the rows of 8.2.2. Every new field is sealed, or arrives in a place a row already names: evs-3 lists the head's sealed ref name and overlay base, which sections 15 and 16 deliver, and evs-12 a push's parts and new objects. `check/`'s metadata test must pass unchanged; 8.8 adds one sentence to evs-4 for what evs can now infer.
- Changeless parts. `evs_statement.go`: `buildParts` adds parts for what does not fit beside the changes, in place of its error "a draft builder adds no part for it", and `build` takes the parts path whenever a one-part payload would pass 1 MiB; such parts carry no `changes_root`. `evs_payload.go`: `evsCheckPartOf`'s "a part with no change" becomes "a part with neither a change nor a section slice, or a part with a change after one without". `evs_merkle.go`: `NewEvsPartedChangeTree` takes only the parts that hold changes. `evsservice/push_part.go` and `push_seal.go`: a changeless part runs no entry check, is recorded and hashed as any part, and the seal's root is over the parts with changes.
- The creating push (evs1-m2-01-ref-creation-fields, option 1). `evs_payload.go`: sections 15 and 16. `evsservice/push_commit.go`: step 7 copies them into the head's `sealed_ref_name` and `base` when the head is absent, a placeholder or deleted; `check_refs.go` refuses them on any other push, a base naming a ref that is not git mode or does not exist at that version, and a base on a file-mode push (409 REF_MODE), and holds the first push after a DELETE to the head's base. `versions.go`'s `OverlayChains` then has chains to read.
- Kinds and gitlinks. `evsservice/check_cas.go`: on a git-mode ref "a directory created over a standing path" and "a file written over a standing directory" are creations, not conflicts; `fold.go`'s `mergeFoldEvents` already lets a creation replace what an entry held, a table included; the task checks the directory-over-file case and tests both. `evs_payload.go`'s entry check, which refuses a file entry with no chain today: a file entry may have an empty chain. `evs_reconstruct.go`: an empty chain is a gitlink when the opened mode is 160000 and refused otherwise.
- Rekey's shape. `evs_plan.go`: `setRef` returns `ErrEvsGitRef` unless every write is a rekey write (`ForceCheckpoint`, `IfVersion`, no `Remove`), and `planPath` then refuses a new blob whose oid is not the standing one's. `evs_push.go`: a git-mode plan seals `git {shape: REKEY}`. `gkm_rekey.go` (KEYS-M2-26, core lane, a wiring change): the git-mode skip goes.
- Tests: vectors for each field; a two-part push whose second part is changeless, committed and read back; a creating push's name and base in the head; a base refused on a second push; a file over a directory on a git-mode ref committing and on a file-mode ref refused; a gitlink entry; a rekey of a git-mode ref from a head-mode client, and one that changes an oid refused by the planner.

**New: EVS1-M2-49, git objects for both directions: the lenient readers, tags, the tree builder, the object sink, and export on them** (sidecar; M).
- `evs_git_object.go`: `EvsGitTreeRead(encoded) ([]EvsGitRawEntry, error)` (git's reading of any tree, with 8.2.5's two refusals), `EvsGitCanonMode`, `EvsGitCommitGraph(encoded) (tree, parents, error)` (commit.c's rule), `EvsGitTag` with `EvsGitTagDecode` (the first `object` and `type` lines) and the `tag` kind in `evsGitObjectOid`. The strict codecs are unchanged.
- `evs_git_build.go` (new, every leg): `EvsGitTreeBuilder` (8.2.7's `build`, over an `EvsGitObjectSource` and an `EvsGitObjectSink`), bounded by `TreeCacheByteCount`. `evs_git_pack.go` (new): the pack writer. `evs_git_check.go` (new): `EvsGitCheckUpdate`, the pure part of `check(u)` that both export and the sync engine call, with the committer resolver and the held-object test as its arguments.
- `evs_export.go`, `evs_export_file.go`: `exportGitRef` reads pushes in parts, takes each tip from `git.new_tip`, replays sources first, rebuilds through the builder (the `states` map and `evsExportState.clone` go), takes history blobs, writes tags, and renders a refused version as 8.5 says. `evsGitObjectWriter` becomes export's sink.
- Tests: 8.6's codec and builder row; export of a history with history blobs, a source, a tag and a raw tree: oids equal, and `git fsck` saying of the export what it says of the original.

**EVS1-M2-34, git to evs** (held; L; scope changed). It keeps net changes, sealed commits, overlays and import, and gains history blobs, sources, tags and the base search. It loses nothing; it needs EVS1-M2-48 and EVS1-M2-49. Order: `evs_local_tree.go` (new: the tree reader over `git cat-file --batch`, `diff`), `evs_local_commits.go` (C, S, B, the spool, the strict checks), `evs_local_publish.go` (`EvsLocalPublish`, the net change, `PlanGitUpdate`'s caller, history segments, the answers of 8.2.5), `evs_local_overlay.go` (the base search, the held set, the whole-directory rule), `evs_local_import.go` (8.2.6). Landed code that changes: `evs_plan.go` gains `PlanGitUpdate(ctx, *EvsGitPlanArgs)` beside `PlanWrite`, sharing `planPath`, with content sources by oid, rename and the two reuse cases (EVS1-M2-25 deferred both); `evs_push.go` and `evs_push_parts.go` take a prepared sealed-metadata builder and extra new objects (the history segments), and re-take the lease when it lapses; `evs_local_mount.go` sets 8.2.11's config and creates `refs/ur/`; `evs_mirror_layout.go` gains the `local/<repo>/` names and their parse. Traps: `old` and the base version are read together under L_r; a ref's own `refs/ur/evs/` tip is in excl, never a source; a queued owned ref is a source only at its evs tip; sources are capped at 16; the spool and the history segments are deleted on every exit; nothing here calls `git diff-tree`; a tag ref never gets a change; `EvsImport` is signed per push, after its commits are fixed. Helper refs (QD-604; 8.2.6), all in `evs_local_import.go`: `oversized`, `split` and `clean`, the helper table in `EvsImportRecord` (a sealed file rewritten whole, durable before a helper's first push), `EvsRepo.Import`'s `Abandon`, and the leftover and unfinished-import lines `ur status` reads; `evs_mirror_layout.go` gains `EvsImportHelperRefName(sidecarId, importId, n)` and its parse beside the conflict branch's. Traps there: nothing of an oversized step is sent; own(q) is counted against `refs/ur/evs/*`, never against local refs; the import holds one publish lock at a time and none across a sub-import; a helper is found by its (merge, parent) pair, never by its number; helpers are deleted only once dst is at the source tip, the most deeply nested first; a helper's DELETE is a push of the import, journaled as kind 3. A new ref's path epoch (QD-632; 8.2.10) comes from section 9's `firstEpoch` (EVS1-M2-50), which `PlanGitUpdate` calls for a ref with no head, reading the base ref's head for an overlay. Tests: 8.6's git-to-evs row.

**EVS1-M2-35, evs to git** (held; L; scope changed). It keeps the sync engine and conflict branches, and gains the dependency on sources, the stop-and-resume rule and the replayed name index. It needs EVS1-M2-49 and, for end-to-end tests, EVS1-M2-34. Order: `evs_local_sync.go` (the replay loop, batches, the wait on sources, `stuck_at`, the resume at a DELETE and the tainted token paths), `evs_local_apply.go` (`EvsGitRef`, the tips log and index, held and born, settle, the two-step write), `evs_local_conflict.go` (the transaction, the bound, the event), `evs_local_index.go` (new: `EvsNameIndex` over the bare repository, registered with EVS1-M2-47's seam at `Mount`). Landed code that changes: `evs_replay.go`: `NewEvsReplayPaths` takes the ref's mode and effective base, and on a git-mode ref holds a creation to b_eff + 1 and takes a creation over a standing path of the other kind; `evs_local_lock.go`: `EvsRefLocks` gains the publish lock and the mount's upkeep lock, and its header's "after evs's 200" becomes 8.2.9; `evs_verify.go`: nothing, the walk is used as it is. Traps: the sink is flushed before `EvsGitRef` moves; settle reads the local ref inside the lock, every time; a conflict's two ref changes are one `update-ref --stdin` transaction; an own push is replayed from the bytes sent but checked like any other; `SidecarCommitter` refusing is a refusal of the version, not an error to retry; the sync engine never takes P_r. Tests: 8.6's evs-to-git row.

**EVS1-M2-36, the receive path** (held; L; scope changed). It keeps the hooks, proc-receive, the journal and owned refs' queue. The journal no longer retries a push id at a restart: it resolves from the history. Order: `evs_local_journal.go` (`EvsJournalRef`, its states, `resolve`), `evs_local_hook.go` (the session, the quarantine relay, pre-receive's checks through EVS1-M2-34's C), `evs_local_receive.go` (proc-receive's protocol on `evs_git_pktline.go`, the per-ref flow, the answers, the queue), `cli/git_hook.go`. Traps: an attempt's record is durable before its first POST; `non-fast-forward` only under G7's condition; `ok` only after the local ref moved; the quarantine paths are checked before the runner takes them; an owned ref's `update-ref` and its journal write are under one L_r; nothing is answered from a 200 alone when the history disagrees; a ref under `ur/<this sidecar>/import/` takes only its deletion (8.2.8). Tests: 8.6's receive row.

**Order.** EVS1-M2-48, then EVS1-M2-49, which uses its messages; then EVS1-M2-34; then EVS1-M2-35; then EVS1-M2-36, as the plan has them. EVS1-M2-35's unit tests need only hand-built pushes, so it can start beside EVS1-M2-34.

**Other tasks this section touches by name.** EVS1-M2-32 (export) is changed by EVS1-M2-49. EVS1-M2-33's files change as listed under EVS1-M2-34 and EVS1-M2-35. EVS1-M2-37 starts `git-receive-pack` with `UR_GIT_SESSION`. EVS1-M2-38's `ur evs import` passes `cuts` and `force`, takes `--abandon`, and adds `ur evs retry`; its `ur status` lines gain an unfinished import and leftover helper refs. EVS1-M2-43 gains 8.6's matrix rows and its twins file. EVS1-M2-47's seam is registered by EVS1-M2-35. KEYS-M2-26 drops its git-mode skip once EVS1-M2-48 lands. EVS2's drop job holds to G11.

### 8.8 Proposed DESIGN.md text

For a design-records track to apply. Each item names its place and gives the text.

**§11.7, "Mapping to git", the paragraph before the table.** Replace "its cleartext changes are the net change per path, and its sealed metadata holds every commit with each intermediate commit's sealed changes, so export rebuilds every original oid" with: "its cleartext changes are the net change of the ref's path state, and its sealed metadata states the update (the ref's value before and after) and carries every commit and blob that the ref's readers do not already hold: each commit's object with its changes against its first parent, any tree that does not rebuild from them as its bytes, any annotated tag as its bytes, and each blob that no entry carries as one sealed history record; what readers hold is what the ref's previous tip, its overlay base and the push's named sources reach, so export and every syncing device rebuild every original oid".

**§11.7's table, new rows after `replay`.**

```text
shapes    a git-mode push is an UPDATE (commits and the net change; FORCE when it does not descend), a DELETE, a
          REKEY (no commit; file entries re-checkpointed, modes and oids unchanged; any writer's device) or a
          PATH_EPOCH; a tag ref (refs/tags/…) holds no path state and its pushes carry no change
sources   a push names up to 16 committed versions of other git-mode refs of the repo whose tips its readers
          replay first; a commit a source reaches is not carried and not judged again; a carried commit is new
          and its committer is the signer's, or it is one of the commits the push's own EvsImport lists
history   a carried blob that is no entry's content is one sealed record in a segment of the push: a checkpoint,
          chunks, or one diff against a blob named by oid that readers hold by then; no entry's chain names it
kinds     a git-mode push may write a file where a directory stands and a directory where a file stands, as a
          creation, removing what was below by its own changes; a gitlink is a file entry with no chain
```

**§11.7's `replay` row.** Replace its text with: "replaying readers of a git-mode ref check TIP; that the update's stated old tip is the ref's; that every carried commit hashes to its oid with its parents held or carried, and that the new tip is their top; descent, except on a FORCE push the refs table allows or when the ref has no tip; each tree against its commit and each blob against its oid; that the changes are exactly the net change to the new tip's tree; and that every carried commit is canonical with the committer `<client_id>@ur.invalid` of the push's client or of a client of its signer (owner decision 81), or is listed by the push's own EvsImport, so the forced identity is a property of the stored history, not only of the hook; a commit reached through a named source was judged where it was carried; PATH_EPOCH and REKEY pushes carry no commit and move no tip".

**§11.7, "Overlays".** Add: "An overlay holds a directory whole or not at all: the first push that adds or removes a child of a directory writes it as a creation listing every child, so a path absent from a held directory's table is absent, whatever its base holds and whether or not a marker stands. A reader resolves a path through the overlay's own entry, then the held tables of its ancestors, then the base. The base is chosen at creation as the nearest version of another branch whose tip the new tip descends from, and never changes."

**§11.8, the `parts` row.** After "within both bounds" add: "a part may hold no change when it holds a slice of the sealed metadata or another section that did not fit beside the changes; such parts follow every part with a change and are no leaf of `changes_root`".

**§11.8, the `seal` row, its last clause.** Replace "an import past 1,024 parts splits at commit boundaries, each push carrying the EvsImport" with: "an import is cut at commits of its tip's first-parent line into ordinary descending pushes, each within 512 parts and each carrying an EvsImport signed for that push's own commits; where one step of that line is too large for a push, the import first brings the merged side into a helper ref of its own, which the step's push names as a source (11.11)".

**§11.6, the statements row and `EvsImport`'s comment.** "EvsImport (evs-import, by a repo admin; 11.11): one push's imported commits: `tip_oid` that push's new tip, `oid_list_sha256` the SHA-256 over its carried commit oids in carried order, `count` their number."

**§11.11, the `import` row.** Replace with: "ur evs import <dir> [<ref>]: a repo admin's daemon fetches <dir>'s history into the bare repository and publishes it itself, not through the hook, as pushes cut on the first-parent line (11.8), each with its own signed EvsImport, into a ref that has no tip or an owned ref of this sidecar; imported commits are held to no committer rule and travel as their bytes, trees that do not rebuild from names, modes and oids included, so history stock git holds imports with its oids; a tree entry whose name holds a slash, a tree naming one entry twice and a tag of a tree or blob are refused before any evs write; where one first-parent step would pass a push's bounds, the import brings the largest merged side into a helper ref, `ur/<sidecar_id>/import/<id>/<n>`, an owned ref of the importing sidecar filled by the same cut pushes, and repeats until the step fits, the step's push then naming the helpers as sources; a side with such a step of its own gets a helper inside its helper, to 8 levels and 64 helpers an import; when the import ends it deletes its helpers, whose history evs keeps, so the pushes that name them stay replayable; one commit that changes more than 1,048,576 entries and a step that needs more than 16 sources are refused, naming the commit; a rerun resumes from each ref's tip and the import's record of its helpers, and `ur evs import --abandon` deletes the helpers of an import that will not be finished". (QD-604.)

**§11.8's refs table and §11.11's `owned` row.** Add: "`ur/<sidecar_id>/import/…` is the import's: the daemon takes no client update of a ref there but its deletion".

**§11.6 and §11.7, a new ref's path epoch (QD-632).** §11.7's "Overlays" gains: "An overlay's first push takes its base ref's current path epoch, so overlay and base share token paths at its creation; each cuts over by its own PATH_EPOCH afterwards." §11.6's text for other refs is in 9.8.

**§11.11, "Refs (D-EVS-28)", the `journal`, `restart`, `owned` and `locks` rows.** Replace with:

```text
journal   per ref update, before any evs write, the daemon records {old, new} in a sealed journal, and before each
          attempt's first POST its {push id, statement hash, base version, time}; from v1 it runs the git-lfs tip
          check on a git-mode tip (below); the proc-receive hook answers `ok` only after the push is in the ref's
          history and the local ref has moved; `ng <ref> non-fast-forward` only when the ref's tip moved and no
          attempt of the update is in the history; the daemon itself signs again when only commitless versions
          (PATH_EPOCH, a rekey) moved the head, re-uploads on SEGMENT_GONE, re-posts on PARTS_MISSING, and waits
          on 429, PATH_EPOCH_DUE and GATE_CLOSED for up to 3 min; unknown -> `ng <ref> remote outcome pending`;
          any other refusal -> `ng <ref> <code>`
apply     a device's refs move only by applying evs's versions in order, its own pushes included: the mirror's
          record of the ref first, then, under the ref's apply lock, the local ref: it follows evs when it is the
          tip last applied or an ancestor of evs's; it stays when it is ahead by an owned ref's queue; otherwise
          its commits go to ur/<sidecar_id>/conflicts/<ref>/<time> in the same ref transaction, EvsConflict is
          raised, and it follows; a conflict branch is published as any owned ref and only its owner removes it
restart   the daemon never sends a statement again: an attempt in the ref's history committed, one whose base the
          head has passed never will (TIP), and one that is neither is pending until its time bound; settle then
          runs for every ref whose local ref is not at the tip applied
owned     ur/<sidecar_id>/… refs are accepted at once (the journal, the local ref, `ok`; the queue pushing within
          250 ms, then at most once per 2 s, one push for everything queued); offline pushes queue, and on
          reconnect the engine seals to the generation then current; a final refusal holds the queue and is shown
locks     a publish lock per ref serializes one device's pushes to it and is held across the network; the apply
          lock covers only local state and is never held across a request; the sync engine takes only the apply
          lock, so receive-pack and sync never race on a ref and neither waits on evs for the other
```

**§11.11, after "Refs".** Add: "The bare repository hides `refs/ur/` (`transfer.hideRefs`), where the daemon keeps each ref's tip as evs holds it, and runs no automatic gc: the daemon runs `git gc` itself, at most daily."

**§11.12, Export.** After "git-mode refs with their original oids" add: "rebuilt from each push's sealed commits, raw trees, tags and history blobs, replaying a push's sources first; a version a replaying reader refuses is reported and skipped to the ref's next DELETE".

**§11.13, the drops rows, D-EVS-64 and §2.8's evs-4.** Add to the drops rows and D-EVS-64: "A drop job's candidates are the segments the chains of its listed versions name, and nothing else: it never sweeps a repo's segments for ones no live version names. A segment a committed git-mode push introduced for history blobs is named by no entry version and stays while its push is retained." Add to evs-4's `sees`: "for a git-mode push, which of its new segments no entry version names, so the padded size of the history blobs it carried"; and to its `ttl`, after "while a retained push names it": "in an entry version or, for a git-mode push's history segments, in its new-objects list".

**§11.5, what the server sees.** Add: "of a git-mode push: its flags and changes, the number of its parts that hold no change, and the padded size of the history it carried; never its commits, its tips or the other refs it names as sources".

**§10.16, v0's `ur evs rekey`.** Add: "On a git-mode ref a rekey is a REKEY push (§11.7): the same job, any writer's device."

**§11.20, Interfaces.** Add `EvsLocalPublish`, `EvsRepo.Import(EvsImportArgs{Dir, Ref, Target, Cuts, Force})`, `ur evs retry`, and the `ng` reasons of 8.2.8.

**§22.5 and FS-5.** FS-5 gains: a push of two commits whose middle blob a second device holds; a pull that names a source; a changeless part; an inherited file removed on an overlay; a rekey under a waiting push; and "a daemon killed after the remote commit reconciles from the ref's history, with no conflict branch".

**D-EVS-28.** "… a durable journal of intent, whose outcomes are read from the ref's history by push id." **New D-EVS-68 (proposed).** "A git-mode push carries what its ref's readers do not hold: commits and raw objects as bytes, blobs as entries or history records, and names the other refs' versions it relies on. *Why:* exact oids on every device and in export; a pull or merge costs its own commit; owner decision 81 checkable by readers." **New D-EVS-69 (proposed).** "A device's git refs move only by applying evs's versions in order under one rule; a local ref that holds what evs's does not goes to a conflict branch, published and never resolved automatically. *Why:* D-EVS-8; no crash, lost answer or race can lose or duplicate an update."

### 8.9 Owner questions

Each is filed under `.stack/questions/`, and the section was built on its recommendation. The owner answered all nine on 2026-11-10: eight on the recommendation, and the ninth on option 2, which 8.2.6 now carries. Each answer follows its question, with its ledger id.

1. **What must an import carry when the codec refuses forms stock git accepts** (`details-8-import-forms.md`; it answers `evs-codec-import-forms`)? Options: (1) keep the three forms refused, as that question recommends: no format change, and a history with a zero-padded mode, which old tools wrote, cannot be imported with its oids; (2) widen the codec for odd modes and late headers: zero-padded modes stay refused, and the committer rule moves into two checks; (3) carry raw: a non-canonical tree and every commit travel as bytes, the path state reads them as git does, and the strict codec applies only to commits a sidecar makes. Cost of (3): `EvsSealedCommit.trees`, a lenient tree reader and graph decoder, and a builder that takes raw trees. **Recommendation: (3).** It imports everything git can walk and a path can name, keeps owner decision 81's rule in one place and strict, and leaves refused only a name with a slash, a repeated name, and tags of trees and blobs. **Answered: QD-598, option 3**, carry raw.
2. **How are a commit's blobs that are not in the net change carried** (`details-8-history-blobs.md`)? Options: (1) one sealed history record per blob, a diff against a blob named by oid, in segments the push introduces; (2) a sealed git pack per push: git's own delta choice, and a pack reader on every leg; (3) not carried: export and `git fsck` fail on any push of two commits. **Recommendation: (1).** It reuses the record and delta code that exists, needs no chain, and costs the diff's bytes. **Answered: QD-599, option 1**, history records.
3. **How does replay know a commit was already in the repo** (`details-8-pulled-sources.md`)? Options: (1) the push names source versions of other refs, readers replay them first, and what a source reaches is neither carried nor judged again; (2) every push carries every commit its ref lacks, and a foreign commit is vouched for by the pusher: any writer can then attribute a commit to another sidecar; (3) hold every carried commit to the signer: no pull and no fast-forward of another's branch can be pushed. **Recommendation: (1).** It is the hook's rule made checkable, and a merge carries one commit. Its cost is that a ref's replay may need other refs' histories. **Answered: QD-600, option 1**, sources.
4. **What does an `EvsImport` sign** (`details-8-import-per-push.md`)? Options: (1) one push's commits, by a hash over that push's own list, one signature a push; (2) the whole import's list, shipped in its first push and kept by every reader until the import ends; (3) as written, unverifiable until the last push. **Recommendation: (1).** **Answered: QD-603, option 1**, one EvsImport per push.
5. **May a part hold no change** (`details-8-changeless-parts.md`)? Options: (1) yes, after the parts with changes, for spilled sections; (2) no, and sealed commits past a part's room go into segments behind a locator: a new record kind and a second way to read commits; (3) no, and a push is capped at about 1,800 commits. **Recommendation: (1).** **Answered: QD-601, option 1**, changeless parts allowed.
6. **How does an overlay remove an inherited path** (`details-8-overlay-directories.md`)? Options: (1) a held directory is whole: its first change on the overlay lists every child, and absence from it is absence; no evs change; one table of up to 448 KiB the first time a directory's names change on a branch; (2) removals on base 0 that write markers, which collection and the path-epoch copy must then keep on overlay refs: three evs changes in other tasks' code; (3) overlays hold their whole tree: creating a branch writes every entry. **Recommendation: (1).** **Answered: QD-605, option 1**, a held directory is whole.
7. **Does a tag ref hold a path state** (`details-8-tag-refs.md`)? Options: (1) no: a tag ref has no base and carries only what its commit needs beyond what its sources hold, so any tag of held history is one empty push, and it never needs a path epoch or a rekey, which an IMMUTABLE ref could not take; (2) yes, as an overlay: a tag at an old commit writes the tree's difference from its base, re-uploading content, and its tokens can never be re-keyed. **Recommendation: (1).** Nothing reads a tag's paths through evs: head mode names no ref and replaying readers use the commits. **Answered: QD-606, option 1**, a tag ref holds no path state.
8. **What is a conflict branch's life** (`details-8-conflict-branches.md`)? Options: (1) made by settle alone, published as an owned ref, never merged, moved or deleted by the daemon, listed by `ur status`, at most 64 a ref before that ref's sync stops; (2) local only: the commits never leave the device; (3) deleted after a period: commits lost on a timer. **Recommendation: (1).** **Answered: QD-602, option 1**, published, and removed only by their owner.
9. **A first-parent step too large for one push** (`details-8-import-step-bound.md`). A merge that brings in more than about a million commits at one step of the first-parent line cannot be one push, and a ref has one tip, so the step cannot be cut. Options: (1) refuse the step in v0, naming the commit and the way round, which uses only sources: import the merged side into a ref of its own, and the step then carries one commit; (2) the import makes those helper refs itself; (3) staged pushes that carry history and move no tip, which readers hold until the step's own push: a fifth shape and staged state in every reader. **Recommendation: (1) for v0**, with (2) addable later without a format change. **Answered: QD-604, option 2, not the recommendation**: the import makes the helper refs itself, under `ur/<sidecar_id>/import/<id>/<n>`, recursing where a merged side has such a step of its own. 8.2.6 gives the naming, the recursion, the cleanup, the resume and the bounds, with no format change; a single commit that changes more than 1,048,576 entries stays a hard bound.

Answered here on an existing question's option, with no new file: `keys-m2-26-rekey-git-mode-refs`, option 1, refined in 8.2.10: evs needs no new rule, and any writer's device can run it. **The owner answered it so: QD-634, option 1**, a commitless REKEY push.

One answer from a build track changes this section's overlays: QD-632 (question `evs1-m2-44-new-ref-crossing`, option 2), a new ref's path epoch, in 8.2.4 and 8.2.10. G11's demand on the drop job is carried forward with QD-626 (question `details-2-drop-job-new-ref`): problem 10's section, which builds to that answer, also holds a drop job's candidates to the segments its listed versions' chains name.

## 9. Client path epochs and re-tokenizing

Status: complete (2026-11-10)

Amended 2026-11-10 for the owner's answers: QD-632 (a ref with no head starts in the epoch its first push names: 9.2.3, 9.2.6, 9.3's P1 and the model, 9.5, 9.6), QD-633 (an inline change list's leaf places: 9.2.2, 9.2.4, 9.2.6) and QD-640 (a head's `index_epoch`, which format-1 code reads past: 9.2.2). 9.9 records every answer, QD-607 to QD-612 and these three. The code these three change is one new task, EVS1-M2-50, in `.stack/plan/proposals/owner-answers-tasks.md`.

Tasks held until complete: EVS1-M2-28, EVS1-M2-29, EVS1-M2-30.

Model: `sidecar/sidecartest/model/details/PathEpoch.tla`, its configurations (`PathEpoch*.cfg`, `PathEpochTwin-*.cfg`, `PathEpochReach-*.cfg`) and `run-pathepoch.sh` beside it. New tasks: `.stack/plan/proposals/details-9-tasks.md` (EVS1-M2-44 to EVS1-M2-47). Questions filed: `.stack/questions/details-9-root-names.md`, `details-9-index-leaf.md`, `details-9-fold-deletes-sources.md`, `details-9-crossing-creation.md`, `details-9-map-source-window.md`, `details-9-map-verifiers.md`. Open questions this section builds on, each on the option 9.9 names: `evs1-m2-24-root-directory-names`, `evs1-m2-16-due-classification`, `evs1-m2-27-every-ref-lease-epoch`, `evs1-m2-10-directory-marker-version`, `evs1-m2-39-head-index-epoch`.

### 9.1 The problem

§11.6 gives every path a token path under a key of one generation, the path epoch, and moves a ref to a newer epoch when a key holder is dropped: a mapper uploads a signed map of every live path's tokens in the new epoch, commits it with a PATH_EPOCH push, and a taskworker job copies each `idx/` entry from the old epoch, now a *source*, into the new one. EVS1-M2-16 and EVS1-M2-17 have landed that on evs: the due, the block, map parts, the PATH_EPOCH commit and the copy. What is left is every client's side: who maps and from what state, what a reader and a writer send while two to four epochs hold a ref's entries, what a push does when the epoch moves under it, and how a version written three epochs ago is still found and still verified. EVS1-M2-28 owns that, and EVS1-M2-29 (deposits) and EVS1-M2-30 (erasure) wait on it because both send pushes through the same sender.

Terms. A ref's *epoch state* is its head's `path_epoch`: the current epoch `cur` and the listed sources. `tp(X, e)` is path X's token path in epoch e. A *cut-over* is a PATH_EPOCH commit. `e(u)` is the path epoch that version u's statement declares. A *holder of e* is anyone with RK_e; §10's ladder opens downward only, so a holder of e holds every epoch below it, and a party dropped at REMOVE generation g holds exactly the epochs below g. A *blocking ref* is a shared or owned ref of a general, config or mailcfg repo, the refs on which evs blocks creation under an immediate due (plan-EVS1-epoch-kinds).

Working it through against the landed code and §11.6's rows found eleven ways it goes wrong. Each is a scenario the design below must close.

**A. A source-epoch token of a new name reaches the server.** §11.6's read row says a client sends a path's token "in each listed source that may hold it", and its map row says a move lists the path's token "in every source the head lists". The landed `EvsRepo.tokenize` (`evs_read.go`) sends every listed source for every path. Device d1 is removed at generation 2; the ref cuts over to epoch 2 with epoch 1 a source for the six hours its copy runs. A member creates `plans/acquisition-of-foo.md`, and any device that then reads it sends `tp(X, 1)`. d1 holds K_path_1 and, with the server's help, tests guessed names against that token, which is exactly what the epoch exists to stop. A mapper that builds the next map while epoch 1 is still listed uploads the same token in a signed part that the server keeps. Nothing in the design says how a client knows which sources "may hold" a path.

**B. After a cut-over, a path last written before it cannot be read, and a change to it can be hidden.** A statement names its changes by token paths in its own epoch. evs's read route (`evsservice/read.go`: `pathReply`, `attachStatement`, `absences`, `olderVersion`) finds a path's change in every statement by the request's current-epoch token path, and the client's verifier (`evs_proof.go`: `VerifyPath`, `verifyUnchangedSince`) checks every statement against that one token path too. Take a file whose newest version was written in epoch 1 by a 3,000-file import. After the cut-over to epoch 2 a read finds its entry (in the source, or moved), and `attachStatement` then looks for `tp(X, 2)` in a change list sorted under epoch 1's tokens: `ErrEvsStatementMismatch`. With an inline change list evs returns the statement and the client's `evsChangeOf` fails instead. Every file not rewritten since the cut-over is unreadable. The other half is a soundness hole: a reader pinned at version 90 reads X at head 130, with the cut-over at 120. A statement at 110 changed X under `tp(X, 1)`. `verifyUnchangedSince` compares that statement's changes with `tp(X, 2)`, finds no match, and accepts the stale version evs served, the rollback I-16 forbids. A listing has its own form of this: an unmoved directory's entry is served from the source with its rows untagged, and `List` opens them under the head's epoch, so every name fails its token check and the reader alarms `tamper`.

**C. A creation lands on a path that stands.** evs holds no key, so while sources stand it can check a creation only against the entries the push names: the current epoch's and the source copies its source paths give. Writer w reads the directory at epoch 1 and sees no `report.md`. Writer v creates `report.md` in epoch 1. The ref cuts over to epoch 2, which folds every earlier version into epoch 1's entries. w's push is refused 412 PATH_EPOCH; w recomputes its tokens for epoch 2 and sends the creation again with no source path, since by its own listing the path never existed. evs reads `idx/2/…`, finds nothing, and commits: a creation over v's file, with no 409, v's content cut off from the path's history. The fold then adds an untagged row beside v's carried row, and when the copy translates the carried row the table holds one token twice, which every reader refuses whole (`EvsOpenNameTable`, `evs_name.go`): the directory can no longer be listed.

**D. Two mappers, two generations.** Device a maps to generation 2 and device b, which has already adopted a second REMOVE rotation, to generation 3, both from a head in epoch 1. a's PATH_EPOCH commits. b's is checked by 5e as written and landed (`pathEpochRules`): a newer generation, parts present, source in the window with a matching chain, tail covering every later creation. It commits. b's map lists each path in epochs 3 and 1 and knows nothing of epoch 2. The copy for epoch 2 has by then moved some entries into `idx/2/` and deleted their epoch-1 copies, and the copy for epoch 3 runs "for the newest map and its tail only": it finds those paths in no source its moves name, and at its end the LIST of `idx/2/` finds entries no move took. It alarms and keeps the source. Nothing ever moves them, one of three source slots is gone for good, and after two more such races every creation on the ref is refused EPOCH_SOURCES_FULL.

**E. A leftover in a source that an honest map will not name.** Closing A means a map lists a source for a path only where the server already holds that token. Then: X is created in epoch 1; cut-over to 2; X is removed and created again in epoch 2, each push's fold writing the current entry and leaving the epoch-1 copy for the copy job (§11.6's "on 412 … its source copies deleted unmoved"; the landed `foldRun.writePath` deletes nothing); before the copy reaches X a cut-over to 3 supersedes it. A mapper sees X as a path created in epoch 2 and lists epochs 3 and 2. The epoch-1 copy is in no move. The source stays listed, as in D. A removed directory leaves the same behind for every child the superseded copy had not reached: no map names a path that no longer stands.

**F. The push that crosses the removal tokenizes a new name under the removed key.** §11.6 records a due at "the first commit whose generation pin crosses a REMOVE generation" and refuses creations "then". The crossing push itself is checked against the head before it (`CheckPathEpoch` reads `view.Head`), so if it creates a path it commits, in the old epoch. §11.6's own Removal paragraph says "none is tokenized under a removed key". And a client that plans a creation first reads the path, which sends the new name's token under the old epoch whether or not the push is later refused.

**G. A removal that leaves its row.** A delta removes a child by token, and a carried row keeps its source epoch's token. A writer that found the file through the current epoch alone removes it with the current token only; the carried row stays, the listing shows a file that is gone, and a later creation of the name gives the table two rows for it.

**H. A mapper that cannot finish.** Parts are immutable and keyed by the map's hash, and a sealed name's nonce is random, so a mapper killed after half its parts cannot regenerate the other half. A map binds a source head that must still be in the head's window, 64 versions at the least, when its PATH_EPOCH commits; a 1M-path map is about 280 MiB, two minutes of upload at 20 Mbit/s, and a ref committing once a second leaves the window in one.

**I. The root has no table.** A top-level name's row has nowhere to live (question evs1-m2-24-root-directory-names), so no mapper can enumerate a file-mode ref's top level and no reader can look a top-level name up through its parent.

**J. History.** `History` asks evs for "version k of this path" by the current token path. A version written in an older epoch sits in a statement that names another token, and the client may not send that token unless it knows the server has it (A).

**K. Slots and closures.** §11.6 has slot ids drawn per statement, and the landed sender rebuilds a push refused 412 PATH_EPOCH from nothing (`evs_push.go`'s rebuild row: "a new push id, sealed afresh"), so re-tokenizing means sealing and uploading again: for a 100,000-file import every segment a second time, and for an erasure's CLOSURE an upload charged twice to the eraser's daily allowance.

The requirement: no token of a name reaches the server under an epoch a removed holder holds unless the server already held a token of that name at or below that epoch; every committed version stays readable and verifiable by a current reader across any number of cut-overs, with I-16's rollback check intact; I-EVS-8 holds across cut-overs for honest clients, and a client that breaks it is caught by replaying readers and cannot break a directory; a ref's sources always drain; and a mapper that dies, races another or loses its window costs time, never state.

### 9.2 The design

#### 9.2.1 The principle

Three ideas carry the section.

**A path has a floor.** For each path it touches, a client keeps the lowest epoch in which it holds *evidence that evs was shown that path's token*: a token evs itself served back, a statement naming it, or a request of the client's own that evs answered. A token of the path may be sent under any epoch at or above the floor, and under no epoch below it. The ladder makes that exactly the requirement: whoever holds an epoch's path key holds every lower one, so a token at or above the floor tells a removed holder nothing the token at the floor did not. A path with no floor is a *new name* to this client. Its token goes under one epoch only, the head's current one as just read, and on a blocking ref not even there while the client knows of a removal that has not cut over (F). Everything else about such a name is learned through its parent directory's table, which evs serves without being shown the name, down from the root, which has no token at all.

**A statement is read in its own epoch.** A version, a removal, a delta or an absence is checked against the statement that made or bounds it under `tp(X, e(u))`, the path's token path in that statement's epoch, which the reader computes for itself from the name and the ladder. The server never needs an older epoch's token to *find* a version it already holds: a folded version carries the place of its change in its statement's list. It needs one only to prove that a later statement of that epoch left the path alone, and every such epoch is at or above the floor.

**One home per path, and one map per source state.** While sources stand, a path's entry lives in exactly one of the listed epochs: whoever writes the current entry (a fold or the copy) deletes the source copies it supersedes, so a source holds only what still has to move. A map is valid for the epoch state it was built on, and evs refuses a PATH_EPOCH across another (the *between fence*). With both, the newest map and its tail name every entry any source holds, and the copy "for the newest map and its tail only" always finishes.

What does not change: the PATH_EPOCH push and its 5e checks other than the fence and the source rule, the copy's order and its states, 412 PATH_EPOCH and its finality, the block, the due, and every key and token derivation.

#### 9.2.2 Formats settled

Format 1 is unfrozen, and every field below is new or re-read. Numbers are next-free in `sidecar/protocol/evs.proto` on 2026-11-10.

```proto
message EvsReadPath {
  repeated EvsSourcePath token_paths = 1;  // the path in the head's current epoch, and in any other epoch the reader
                                           // may name (9.2.3): a listed source's is read for the entry (11.6's read
                                           // rule), and each one serves the statements of its epoch; at most 8; evs
                                           // matches by the epoch field, never by position
  uint64 version = 2;                      // 0 the newest committed, else that older version of the path
  uint64 commit_version = 3;               // with version: the ref version its push committed at, from the newer
                                           // version's prev_commit_version; 0 unknown (9.2.4's history)
}
message EvsReadPathReply {
  ...
  uint64 entry_epoch = 17;                 // the epoch whose idx/ copy served the version, table or marker; 0 the
                                           // head's current one
  bool stale_epoch = 18;                   // the request named no token path in the head's current epoch: nothing
                                           // was read for this path, and the reader asks again on this head
}
message EvsIndexVersion {
  ...
  uint32 leaf_part = 5;                    // where its change sits in its statement's list: the part, 0 for a
  uint32 leaf_index = 6;                   // one-part push and for an inline list, and the change's index in
                                           // that part's list, or in the inline list, plus 1; leaf_index 0
                                           // means only "not recorded": an entry folded before the fields
                                           // existed (question evs1-m2-45-inline-leaf-place, QD-633)
}
message EvsRemovalMarker {
  ...
  uint32 leaf_part = 6; uint32 leaf_index = 7;  // the same, for the change that removed the path or its prefix
}
message EvsIndexEntry {
  ...
  uint32 names_leaf_part = 7; uint32 names_leaf_index = 8;  // the same, for the delta at names_through (6 is left
                                           // for evs1-m2-10-directory-marker-version's names_version)
}
enum EvsRefusalCode {
  ...
  EVS_REFUSAL_MAP_SOURCE = 75;             // 409, final: a PATH_EPOCH whose map's source is unknown, under another
                                           // chain or of an epoch no longer current, or a map part whose key holds
                                           // other bytes (9.2.6); the landed code answers MAP_PARTS for these, which
                                           // a mapper cannot tell from "upload the parts again"
}
```

`EvsPush`, `EvsPathMap`, `EvsPathMove`, `EvsSourcePath`, `EvsName` and `EvsHead` keep their fields. `EvsHead.index_epoch` (24) and `EvsHeadSummary.index_epoch` (15) are the search index's, not a path epoch: a head carries one only once an erasure's CUT committed. Format-1 code reads past both (question evs1-m2-39-head-index-epoch, option 1; QD-640): the summary's is on `testdata/evs/reserved_numbers.yml`'s ignored list and the head's on its kept list, since a format-1 write carries it forward and evs's head rule keeps it from falling. Nothing in this section reads it: a PATH_EPOCH push names no index epoch and its commit leaves the head's as it was, a map and the copy move `.ur-index/` entries like any others, and a format-1 device goes on reading a ref's format-1 files after a CUT. What this section adds to these messages is rules, for `protocol/EVS-FORMAT.md`:

```text
map       one move per path live at the source head S, the root included (9.2.8), ascending by new_token_path's
          bytes within a part and across parts, so a part is a run and the copy can take them last part first; a part is
          at most 8 MiB signed, and a map at most 1,024 parts; a move's sources are
          the path in the epoch current at S, then in each source S lists that 9.2.7's rule names, newest first;
          sealed_name is the name under manifest_{p_new}, AAD repo_id || u64be(p_new) || new parent || new child,
          and empty for the root; path_map_sha256 is SHA-256 over the parts' signed bytes in part order
tail      one move per token path that a version in (S, b] created, b the PATH_EPOCH push's base, whether or not the
          path still stands, ascending; its sources name the current epoch alone
source    a change's source paths (payload section 12) name the path in each listed source at or above its floor
paths     (9.2.3), never another; a removal delta's removed_tokens hold the child's token in the current epoch and in
          each of those sources
leaf      a fold records leaf_part and leaf_index from the list it folds, inline or rooted: an inline list's
          places are part 0 and the change's index in the statement's list plus 1; a carry (a fold's or the
          copy's) keeps them
first     a ref with no head starts in the epoch its first push names (9.2.3, 9.2.6): the newest REMOVE
          generation its creator holds, 1 when there is none; an overlay's, its base ref's current epoch; a
          deposit or erasure ref's, 1
```

Client state, all local and sealed under §5's AEAD:

```text
EvsReadRecord   gains Floor (the path's floor, 0 none) and PinEpoch (the ref's current epoch at PinVersion);
                HeadReadRecordCount and its eviction stay
ref epoch       per (repo, ref), in memory: the epoch state of the last verified head and the time it was verified
listing cache   per (repo, ref, head version, directory path), in memory, at most ListingCacheCount = 256: the
                opened rows of a verified listing, each with its epoch
map job         evs/epoch/<repo>/<ref>/job: EvsMapJob {p_new, source_version, source_chain, source_epoch, sources,
                path_map_sha256, part_count, uploaded (a bit per part), built_ms, state, tail_refusals};
                evs/epoch/<repo>/<ref>/part/<k>: part k's signed bytes as they are uploaded (9.2.7)
born journal    per ref a mapper follows: path -> the epoch its standing creation committed in, for creations after
                the cut-over that listed the oldest source standing; empty while no source stands (9.2.7)
```

Settings, in the client's `EvsSettings` unless marked evs:

```text
EpochFreshFor            5 s     a new name is tokenized only on a head verified this recently
ReadEpochCount           8       token paths per path in one read request
ListingCacheCount        256
MapperSpread             10 min  the random delay of a mapper that did not rotate
MapperBatchedLead        2 h     a batched epoch is mapped this long before due_by_ms
MapPartFillByteCount     7 MiB   a part is closed at this size (2 MiB on mobile, inside R-EVS-14's 4 MiB)
MapUploadCount           4       parts at once (2 on mobile)
MapMaxAge                20 h    a map whose oldest part is older is abandoned (evs adopts under 24 h)
MapTailRefusalCount      2       tail refusals before a block is asked for
MobileMapNameCount       100,000 §11.6's bound on a mobile mapper
EpochOverdueAfter        1 h     §11.6's alarm
evs: MapSourcePageCount  1       log pages a PATH_EPOCH check may read for its source (9.2.6)
```

#### 9.2.3 Floors and the two token rules

A floor is lowered only by evidence, and there are exactly four kinds:

```text
E1  a verified version or removal of X whose statement declares epoch e and names tp(X, e): in its inline list, or
    as the leaf of the proof evs sent, compared with the reader's own tp(X, e)                              -> e
E2  a verified row of X in its parent's table, its token equal to the reader's own for the row's epoch:
    a carried row's epoch; an untagged row's table epoch (entry_epoch, or the current one)                   -> that
E3  a request of this device that named tp(X, e) under the rules below and that evs answered, with any status
    (a 412 PATH_EPOCH is an answer; a transport failure is not)                                             -> e
E4  a verified version of X naming prev_push_id, and that push's statement, verified, declaring epoch e:
    a writer signed that the path's previous version was written there                                      -> e
floor(X) = the least of: its read record's Floor; a cached listing's row for it (E2); what the call in progress has
           gathered (E1, E3, E4). None of them: no floor. A lost record loses the floor, which only sends less.
```

A directory's floor is never above a child's, since a request or row that shows a child's token path shows the directory's. The root has no token and needs no floor.

**The floor rule.** For a path with floor f on a ref whose verified epoch state is (cur, S), a request may name `tp(X, e)` for e = cur, for each s in S with s ≥ f, and for any other e ≥ f it needs a proof under (9.2.4). It names no epoch below f.

**The new-name rule.** For a path with no floor, a request may name `tp(X, cur)` and nothing else, and only when both hold:

```text
fresh     the epoch state was verified within EpochFreshFor, else the client first reads the head alone
quiet     on a blocking ref: pressure(ref) is not immediate
pressure(ref):
  the head records a due with due_generation > cur            -> immediate if due_blocks_creation, else batched
  else r = the newest generation g in (cur, g*] this device holds whose GenRotate cause is REMOVE (RepoKey(g))
       none                                                    -> none
       classed by evs's own rule (epoch_commit.go's pathEpochDueOver, moved to a root function both call:
       immediate unless this device's verified state shows holders_shrunk_at at or below the auth pin of the
       generation crossed from; question evs1-m2-16-due-classification, option 1)
```

A read of a no-floor name additionally needs S empty; otherwise the directory decides first (9.2.4). A push needs no such condition: its creation is checked against the directory it read.

`quiet` is what closes F on the client, where alone it can be closed: a device that holds the removal's generation is the device whose push would cross it, and it sends no new name under the old epoch, in a read or in a push. It waits for the epoch as it would on 412 PATH_EPOCH_DUE, and maps if it can (9.2.7). A batched due does not hold new names, as §11.6 has it.

What the rules leave is one window, stated here and in §11.5: a new name's token sent on a head at most `EpochFreshFor` old can reach evs after a cut-over committed in between. It is refused or answered on the new head either way; the token under the epoch just left is one a holder dropped by that cut-over can test.

**A ref with no head** (question evs1-m2-44-new-ref-crossing, option 2; QD-632). A ref does not start in epoch 1: it starts in the epoch its first push names. Every path of a first push is a new name on that ref, and the head the new-name rule reads is absent, so its creator names the epoch by this rule in place of `cur`:

```text
a ref that is no overlay    p = the newest generation r <= g that this device holds whose GenRotate cause is
                            REMOVE (RepoKey(r), walked down from g as pressure walks it), g being the generation
                            the push seals to; none: p = 1
an overlay                  p = the current epoch of its base ref R, from R's head verified within EpochFreshFor;
                            the creator holds RepoKey(p), else ErrGkmKeyMissing as for any read
a deposit or erasure ref    p = 1, as below
fresh                       the head read that found no head, within EpochFreshFor
nothing is read             a ref with no head holds no entry: the planner sends no path request for it, and
                            every change is a creation; the first push's token paths, under p alone and with no
                            source path, are the first tokens evs sees under the ref
```

On a ref that is no overlay `quiet` holds by construction: p is the newest removal the device holds, so no REMOVE generation lies in (p, g] and pressure is none. A later REQUEST or SCHEDULE generation drops no holder, which is why the rule names the newest REMOVE generation and not g: a holder that has r but not yet g still reads the ref. A removal the creator has not been told of is §11.5's bound, as on any ref.

On an overlay the floor rule and the new-name rule apply as they do on its base, with p for `cur`. A repo's refs share their path keys, so an inherited path has its floor from the base ref (8.2.4) and its token under p is one evs holds already. A name new to the repo is held by `quiet` against the base ref's pressure: while the base ref is under an immediate removal the overlay would start in the epoch the base is about to leave, so its creator waits for the base's cut-over as it would on 412 PATH_EPOCH_DUE, and then names the base's new epoch. A first push that holds only inherited paths would send no new token, but evs cannot tell it from one that does (9.2.6), so the creator holds every first push of an overlay that carries a change while its base ref's pressure is immediate. Overlay and base then share every token path at the overlay's creation; each ref cuts over by its own PATH_EPOCH afterwards, and a reader works each in its own epoch state.

A first push is planned on the belief that the ref holds nothing, and it commits only as the push that creates the ref (9.2.6). When the ref has a head by the time the push would be sent, or by the time it lands, the plan is dropped and made again on the head then read, as a plan on any ref is: each path read through 9.2.4, each creation checked against its parent's listing. It is never retokened. And a request on a ref with no head sets no floor: E3 does not count it. Both matter for one case. Two devices create the same ref; one names epoch 2, and the other, which has not yet been told of the removal, names epoch 1 and lands first; a mapper cuts the ref over to epoch 2, and the copy has not run. If the first device's push were then taken, or retokened with the floor its own refused attempt gave it, it would name epoch 2 and no source, evs would find no entry for a path the other device created in epoch 1, and the creation would land on a file that stands. Planned again, the device finds that file's row in the listing. Forgetting what a request on no head showed evs only sends less (9.2.3's rule for a lost record). An overlay's first push refused 412 PATH_EPOCH because its base ref's epoch moved is the one first push sent again as it is, under the base's new epoch: its own ref still holds nothing.

Deposit and erasure refs have neither floors nor rules: their entries are random ids under no path key, they stay at epoch 1 for life (plan-EVS1-epoch-kinds #2), and every request on them declares epoch 1.

#### 9.2.4 Reads

```text
read(X, want):                                    // want: newest, or version k
  E = (cur, S), the epoch state of the ref's pin; none held (a first read, a restart): read the head alone
      first, verify it and pin it
  f = floor(X)
  if no f:
      if S is empty and the new-name rule holds:  ask = {cur}
      else:                                       row = lookup(X)
                                                  if no row: return absent        // no token of X was sent
                                                  f = row's epoch                 // E2
  if f:  ask = {cur} ∪ {s ∈ S : s ≥ f} ∪ {record.PinEpoch, when X has a record and PinEpoch ≥ f}
  send; verify the head; if its epoch state is not E: pin it, adopt its state, drop the paths' replies and
      start again
  verify the path (below); raise E3 for each epoch asked
  a version or a removal:                         return it                       // conclusive
  nothing, and S ⊆ ask:                           return absent                   // conclusive
  nothing, and some source was not asked:         row = lookup(X); no row: absent; else f = row's epoch, again

lookup(X):                                        // X = P/name; sends no token of X
  L = the verified listing of P at the head: the listing cache, the mirror, or read(P) and list
  P absent or removed: none
  the row whose opened name is `name`: its epoch (E2), else none
```

A lookup recurses to the first directory that has a floor, and at the latest to the root. Each level is one round at most, cached for the head version, and a mirror answers all of them locally. Up to 64 paths share a request, each under its own rule.

**The route.** evs matches a request's token paths by their epoch field. The entry is read by §11.6's read rule from the current epoch's and the listed sources' token paths. A request naming none in the head's current epoch gets `stale_epoch` for that path and the head, nothing read. `entry_epoch` says which copy served. For the statements it must speak for, evs works in each statement's epoch:

```text
the served version, removal, or the delta at names_through, committed at u:
    u after the newest cut-over: found by the current token path, as today
    else by leaf_part and leaf_index: the change at that place of its statement's list, whose EvsEntryVersion
        bytes the push record holds in the list's order; under a rooted list the proof's leaf is the EvsChange
        itself; an inline list (part 0, the index plus 1) needs no proof, the statement holding the list
    leaf_index 0, an entry folded before the fields existed: the statement alone, as History's answer below
each returned statement w after max(u, pin_version) whose list is under changes_root:
    the request names a token path in e(w): digest, covering prefixes and adjacent-leaf proofs under that path
    it names none: nothing for w
window versions after folded_through: all of the current epoch (9.3's W1), read by the current token path
```

**The reader.** `tp(X, e)` below is always the reader's own, from the name and RK_e.

```text
verifyPath(X, reply, walk W):
  a version at u, or a removal at u:   e = e(u); the change is the one for tp(X, e): in the statement's inline
       list, or the proof's leaf, whose token path must equal tp(X, e), or for a removal be a prefix of it; hash,
       version and removal rules as §11.9's reader row; E1
  since = max(u, pin(X)); pin(X) is the record's PinVersion, else the ref pin before this read
  each walked statement w in (since, H]:   e = e(w)
       inline:  no change of tp(X, e), and for a standing path no removal of a prefix of it
       rooted:  for each path p of EvsAbsencePaths(w.changed_prefixes, tp(X, e)): the absence proof for (w, p);
                missing, and the request named e: refuse; missing, and it did not: add e to `more`
  `more` is not empty: ask once more, naming those epochs too; each is at or above e(u), so at or above the floor
  a directory: untagged rows open under entry_epoch (0: cur), carried rows under their own epoch, a delta's rows
       under its statement's epoch, and a delta below the walk under cur (9.3's W1)
  then pin, and write the record: Floor, PinEpoch = cur
```

With the place recorded for inline lists too (question evs1-m2-45-inline-leaf-place, option 1; QD-633), evs serves every committed version in one round after a cut-over: a directory whose newest delta an inline push of an older epoch wrote, and a version kept elided, included. Most directories are such, since a small push's list is inline. The statement-alone answer is left for an entry with no recorded place: the reader finds its own token path in the inline list, which is evidence evs holds it (E1), names that epoch and asks again.

A path with no record is checked from the ref pin, and `read` goes on only when the reply's head has the pin's epoch state: the current epoch only rises, so no cut-over lies between them and the walk holds statements of the current epoch only. That is §11.9's trusts row and g0-recheck-0-head-reader-read-paths as they stand: what a never-read path was before its first read is evs's word.

**History.** A version beyond the newest is asked by number with `commit_version` from the newer version's `prev_commit_version`. evs serves it from the entry's folded versions by their leaf places, or from the push record at `commit_version` by the request's token path in that statement's epoch. When the request names none for that epoch, the reply carries the statement alone. The reader checks its push id against `prev_push_id`, which is E4, and asks again naming that epoch. The walk costs one more round per epoch boundary it crosses.

#### 9.2.5 Writes and re-tokenizing

The planner (`evs_plan.go`) no longer refuses a write while sources stand. Per push:

```text
plan(writes):                                  // file mode; the local tier does the same per net change in git mode
  the head, read fresh: E = (cur, S); the key from EnsureWritable, whose generation is at least cur
  for each path X the push writes:
     v = read(X)                               // 9.2.4: its standing version or absent, and floor(X) with it
     create (v absent):
         X's parent's listing holds no row for the name: read(X) looked it up, or the planner does now       (C)
         a blocking ref under immediate pressure: ErrEvsPathEpochDue, and no token of X is sent              (F)
         change {tp(X, cur), base 0}; the parent's delta adds {child token in cur, kind, the name sealed in cur}
     modify:  change {tp(X, cur), base v}
     remove:  floor(X) = min(floor(X), the epoch of its row) (E2); change {tp(X, cur), base v, no entry};
              the parent's delta removes the child's token in cur and in each s ∈ S with s ≥ floor(X)         (G)
     the change's source paths: tp(X, s) for each s ∈ S with s ≥ floor(X); none for a path with no floor
  a directory a delta touches: its own change's source paths, by the directory's floor
  statement.path_epoch = cur
```

A directory that does not stand is created on the way, as today, and is a new name like any other.

The sender (`evs_push.go`, `evs_write.go`) gains one path beside retry and rebuild, the *retoken*:

```text
412 PATH_EPOCH (final for its statement; 5e):
   every path the push named, in a change, a source path or a delta's row, takes floor min(floor, the push's
       path_epoch): evs answered a request that showed them there (E3)
   wait for a verified head whose current epoch is above the push's, and for RepoKey of that epoch
   retoken(plan, that head):
       kept        every sealed byte: segments and their receipts while under 22 h old, slot ids and slot bodies,
                   inline records, sealed fields, chains, sealed metadata, and each change's base_entry_version
       made again  token paths in the new epoch; source paths and removed tokens by the floors just lowered; the
                   added rows' names, sealed in the new epoch; entry versions (push id, base_version, a creation's
                   max(b, m) + 1 on the new base); the change list, roots and covering prefixes; a new push id and
                   time; the statement; every part
       not read    no path is read again: 5g holds each base, and a path that moved since the plan answers 409
                   as on any push
   a creation on a blocking ref whose pressure is immediate again waits, as below
   a statement whose generation the gate no longer takes goes to 412 GATE_CLOSED's rebuild, which seals again
412 PATH_EPOCH_DUE, and ErrEvsPathEpochDue from the planner:
   try again at retry_after_ms, at a PATH_EPOCH hint and at each newly verified head; a device that can map does
   (9.2.7); past EVS1-M2-26's wait bound the caller gets EVS_PATH_EPOCH_DUE
```

A retoken counts against `PushRebuildCount` with rebuilds. The lowered floor is what closes C: w's second attempt names `report.md` in epoch 1, evs reads v's file there, and the creation answers 409.

Keeping the slot ids changes §11.6's slot rule, which today draws new ones for every rebuilt push. A push refused 412 PATH_EPOCH never commits, since the epoch only rises; its slot bodies are the bytes the retoken sends again; and step 6 already takes equal bytes on a 412 as success. A slot object an attempt of the refused push left is adopted by the retoken exactly as a segment's receipt is (under 23 h, else 409 SLOT_STALE and the ordinary rebuild). So a CLOSURE is uploaded and charged once (K).

Format 2's kind-5 segment names its push in its header, so a retoken cannot adopt one and uploads it again. That is EVS2's to carry; format 1 has no such segment.

#### 9.2.6 evs

Five changes to landed code, four small.

**The fold deletes what it supersedes.** While the head lists sources:

```text
for each path X with a change in the fold's range (f, u], once its current-epoch entry holds that change
(written by this fold, or found already holding it):
    named = the source paths of X's changes in the range whose epoch the head still lists
    DELETE idx/<repo>/<ref>/<s>/<tp(X, s)>.e for each, unconditional, under 11.7's stale deadline; a 404 is done
    if X's newest change in the range removes a directory:
        for each named s: LIST idx/<repo>/<ref>/<s>/<tp(X, s)>/ and DELETE every key under it
a fold's range is folded, so that its process may raise folded_through over it, only once these have answered
```

The order is the copy's own: the current entry stands before a source copy goes, so §11.6's read rule ("if every GET of the path returned 404 it GETs the current one again") covers a fold's delete as it covers a move's. What stands at the current epoch after a removal is the marker, which §11.7 already puts before any LIST below it, and under which no read falls back to a source. The deletes are part of the fold so that a process killed between its PUT and its DELETE leaves a range another fold runs again; that fold finds the entry holding the change and still deletes.

**5e for a PATH_EPOCH: the source and the between fence.** In place of "its source version is in the window with a matching chain":

```text
source    St_S, the statement at map_source_version S, and C_S: from the window when it holds S, else from log page
          ⌊S/64⌋, one cached GET, C_S recomputed from the page's first_chain; S ≤ v and C_S = map_source_chain,
          else 409 MAP_SOURCE, final
between   the epoch St_S declares (a PATH_EPOCH statement's is its p_new) is the head's current epoch, else 409
          MAP_SOURCE, final: an epoch committed after the map's source, and the mapper maps again
tail      every token path that a version after S which the head's window holds creates is a tail move's
          current-epoch source, else 409 naming the paths, final (as landed); a creation between S and the window
          is the mapper's to cover, which read every version through its base b, and b is in the window
```

Everything else of 5e stands: a newer generation, parts present and under 24 h old, the source slots, nothing unfolded. The epoch only rises at a cut-over, so "the source's epoch is the current one" is exactly "no PATH_EPOCH committed after S".

**The crossing creation.** 5e for any other push computes the due its own commit would record (`pathEpochDueOver`). If that due blocks creation and the push creates a path, evs answers 412 PATH_EPOCH_DUE and records it, and the refusal's fence write sets the head's due fields as the commit would have. The first push across a removal then stops creation whether it commits or not, and no committed statement creates a path on a blocking ref under an epoch below an immediate removal its own pin covers.

**A ref's first push** (question evs1-m2-44-new-ref-crossing, option 2; QD-632). On a ref with no head, absent or a placeholder a refusal or evacuation left, 5e no longer requires epoch 1 and no longer exempts the push from the crossing creation, which is what EVS1-M2-44 built. With p the push's `path_epoch` and g its generation:

```text
once      a push planned on no head (base version 0, the creating sections 15 and 16) on a ref that has a
              head: 409, final, before its epoch is compared: BASE_STALE in file mode, non-fast-forward in git
              mode; its sender plans again on the head (9.2.3)
epoch     a deposit or erasure ref: p = 1 (plan-EVS1-epoch-kinds #2)
          an overlay, its base (R, k) in payload section 16: p = the current epoch of R's head as step 4 read
              it, and p <= g
          any other ref: 1 <= p <= g
          else 412 PATH_EPOCH, final, as for any push that names another epoch than the head's
crossing  the due is computed from p as on any ref: gen/<k> for k in (p, g], the newest REMOVE among them,
          classed by the pin of gen/<p>; a due that blocks creation, in a push that creates a path -> 412
          PATH_EPOCH_DUE, recorded in the placeholder head; no due is written, there being no head to carry
          one, and the next attempt computes it again from its own pin
the base  an overlay's first push that creates a path while R's head blocks creation (its due_blocks_creation,
          or before its block_until_ms) -> 412 PATH_EPOCH_DUE, recorded the same way: the overlay would start
          in the epoch R is about to leave
commit    step 7's new head carries path_epoch {current: p, no source}, with the due of the line above when one
          was computed that does not block (a batched one, or a ref kind that never blocks), and none for any
          generation at or below p
PATH_EPOCH on a ref with no head: 409 MAP_SOURCE, as landed
```

The `once` line is what keeps path-level CAS whole at a ref's creation. Every other push is held to the head it was planned on by its epoch, since the epoch only rises at a cut-over; a push planned on no head names an epoch of its own choosing, which a later cut-over can reach, so it is held to "no head" directly.

An honest creator names the newest REMOVE generation it holds, so (p, g] holds none, the first push records no due and creates freely. The crossing line is for a creator that names less: its refusal wedges nothing, since the same device holds gen/<k> for every k up to its own pin and sends again naming the generation the refusal crossed. So the sentence above holds of first pushes too, and "no committed statement creates a path under an epoch below an immediate removal its own pin covers" has no exception. An overlay whose base ref is under an immediate removal is refused by the base line, or by the crossing line when its own pin crosses that removal, until the base cuts over, as 9.2.3 has its creator wait. evs cannot tell an inherited path's first entry on an overlay from a new name, both being creations there, so the wait covers both, as the block already does on an overlay that has a head.

A ref deleted by a DELETE push has a head, with its epoch state, and the push that creates it again is an ordinary push in that head's current epoch.

**The read route** is 9.2.4's: token paths matched by epoch, `stale_epoch`, `entry_epoch`, proofs by leaf place or by the request's token path in the statement's epoch, `commit_version`. The fold writes `leaf_part` and `leaf_index` into each folded version, marker and `names_leaf_*`, for an inline list as for a rooted one (part 0, the index plus 1; QD-633), and a carry keeps them.

**The copy checks its map.** `copyRun.loadMoves` hashes the parts as it reads them and compares with the head's `map_sha256`; on a mismatch, or a part out of 9.2.2's order, it moves nothing, alarms and ends, and the source stays listed. evs verified each part's signature at its upload, and a reader checks every row and entry it uses (9.3's M1), so this is the one whole-map check, made where the map is read whole anyway.

**The order of the fences.** Each line is the order in which one actor meets them, and a later one never stands in for an earlier.

```text
a request      the client: a head verified within EpochFreshFor and no immediate pressure (a new name only); then
               the floor rule for every token path it names
a push at evs  5d the gate; 5e a push planned on no head, on a ref that has one (409, final); 5e the epoch (412
               PATH_EPOCH, final; on a ref with no head, the epoch its first push may name); 5e the crossing
               creation, the due and the block (412 PATH_EPOCH_DUE, recorded); 5f the base; 5g the path-level CAS
               over the current entry and the source copies named; step 7
a PATH_EPOCH   the mapper: the job record, the parts, the replay to its base, the tail; evs: 5d; 5e a newer
               generation, a free source slot, the parts present and under 24 h, the source and its chain, the
               between fence, the tail over the window, nothing unfolded; 5f; step 7 with folded_through = v
after a commit the fold: PUT the current entry, DELETE the named source copies, and only then may folded_through
               rise; the copy: children before their directory, PUT the current entry, HEAD its prefixes, DELETE
               the source copies; at its end the LIST of each source, then the fence write that drops them
```

#### 9.2.7 The mapper

A mapper is a writer that holds every name of a ref. It is given them by an index:

```go
// Every name of a ref as of one replayed head. On every leg.
type EvsNameIndex interface {
	// The head the index is exact at: its version, chain and epoch state.
	Head(ctx context.Context) (*EvsNameIndexHead, error)
	// Every path standing at that head, a directory before what it holds: its raw names, kind and born epoch.
	Walk(ctx context.Context, visit func(path *EvsIndexedPath) error) error
	// Every path a version in (version, Head] created, standing or not, with its names.
	CreatedAfter(ctx context.Context, version uint64) ([]*EvsIndexedPath, error)
}
```

`born` is an epoch in which evs was shown the path's token and which is at most the epoch of the path's row, or 0 for a path that stood before the oldest standing source was left, for which every listed source qualifies. Two kinds of index give it, and either is correct:

```text
replayed   the local tier's mirror of a mounted repo, or a head-mode mirror: it follows every statement, and its
           born journal holds, for each path created after the cut-over that listed the oldest standing source,
           the epoch that creation committed in; a path not in the journal stood before, and born is 0; a removal
           drops the path and everything below it from the journal; the journal empties when the sources drop
listed     evsListedNameIndex, which EVS1-M2-47 builds for a device with no mirror: it lists the tree from the
           root by 9.2.4 (64 directories a request), taking each row's epoch as born (E2), then lists again every
           directory a statement after its listing changed, until one verified head has no such statement; after
           8 rounds without one it gives up until the next tick. CreatedAfter never comes from listings, which
           miss a path created and removed between two of them: it reads each creating push's record (§11.9's
           push reads) and opens the rows its directory deltas add
```

A device is *eligible* for a ref when it writes the repo, the ref is shared or owned, and an index is registered for it: on a phone only while the index holds at most `MobileMapNameCount` names. Wrapped agents are eligible on the same terms (owner decision 114).

```text
tick(ref), on a new generation from gkm, a verified head, a PATH_EPOCH hint, and a timer:
   E = the head's epoch state; g* = the newest generation held
   r = the newest REMOVE generation held above E.cur, or the head's due_generation; none: delete any job; idle
   not eligible: only 9.2.8's alarm
   g* below r (the head records a due this device holds no key for yet): wait for gkm's delivery
   a job on disk: resume it at its state
   batched, and E lists two sources: wait, building nothing                      (§11.6's commit row)
   E lists three sources: wait
   start at: now, for a device whose own EnsureWritable call returned r; else, immediate: first seen + U[0, MapperSpread);
             batched: due_by_ms − MapperBatchedLead + U[0, MapperSpread), due_by_ms being 24 h after the
             device first held r when no head records the due; U seeded by (sidecar_id, ref_id, r)

build:     S = index.Head(), whose epoch state must be E; p_new = g*
           walk the index ascending by new token path, a part at a time: per path the move
               {tp(X, p_new); sources: tp(X, cur), then tp(X, s) for each s ∈ E.sources with s ≥ born(X), newest
                first; the name sealed in p_new}
           each part signed, written to part/<k>, hashed into path_map_sha256; then the job record, state
           uploading, durable before the first byte is sent
upload:    POST .../path-epoch per part not yet marked, MapUploadCount at once; a 200, or equal bytes standing,
           marks it; MAP_SOURCE (other bytes under the key) abandons
commit:    replay to the head b; abandon unless b's current epoch is the job's source_epoch
           tail = a move for each path of index.CreatedAfter(S)
           the PATH_EPOCH push on b: p_new, generation g*, map_source (S, C_S), path_map_sha256, path_tail_sha256;
           git mode on the tip, taking the seal lease first when the last attempt lost the tip
   200                              done: delete the job; leases and floors follow the hint (9.2.8)
   409 naming paths (the tail)      a new head, a new tail, a new push id; after MapTailRefusalCount of them and
                                    10 min past due_by_ms: POST .../path-epoch/block {ms: 120,000}, then push
   409 MAP_SOURCE                   abandon and build again: an epoch landed, or the source is gone
   409 MAP_PARTS (recorded)         upload the parts again from part/; a second one abandons
   412 EPOCH_SOURCES_FULL           wait for a head listing fewer sources, the job kept
   412 PATH_EPOCH                   an epoch at or above p_new stands: done
   412 GATE_CLOSED                  EnsureWritable, then the same map under the newer generation's pin
abandon:   delete the job and its parts, and tick again. Also when the head's current epoch reaches p_new, when the
           oldest part passes MapMaxAge, when gkm delivers a REMOVE generation above p_new before the commit, and
           when the device stops being eligible
```

A restart resumes from the job record: the parts on disk are the bytes the map's hash names, so an interrupted upload continues where it stopped and never needs a nonce drawn twice (H). Uncommitted parts on evs are section 2.2.5's to delete.

Two mappers need no agreement. If both map to one generation, the first PATH_EPOCH commits and the second answers 412 PATH_EPOCH. If they map to different generations from one source head, the second meets the between fence and maps again from the new state (D). `MapperSpread` only keeps them from uploading the same megabytes at once.

#### 9.2.8 The root, leases, the alarm and what a caller sees

**The root** is a directory whose token path is empty (question evs1-m2-24-root-directory-names, option 1): its entry is `idx/<repo>/<ref>/<p>.e`, a change may name the empty path only for a directory delta, and a read may name it. This section adds what a path epoch needs of it. The root's token path is the same in every epoch, so any client may read it at any time and it has no floor. Its rows are per epoch like any directory's: a top-level name's row holds its token under K_path_p with parent t_0. A map holds a move for the root, first in part 1, with an empty new token path, an empty path in each source and no sealed name, and the copy moves it last, after every child, translating its rows as any directory's. EVS1-M2-46 builds it.

**Leases.** A prefixed lease is created in the head's current epoch and names its prefix's token there, under the floor and new-name rules like any request; a lease never names a source epoch. On a PATH_EPOCH hint or a resync that shows a new epoch the holder creates its leases again, which EVS1-M2-27 has landed. A lease on every ref with no prefix names no token, and this section builds on evs matching it in every epoch (question evs1-m2-27-every-ref-lease-epoch, option 1).

**The alarm.** A device that writes the repo raises `evs_alarm` with reason `epoch_overdue` when a verified head shows a due whose `due_by_ms` is over `EpochOverdueAfter` past, at most once per ref and due generation in 24 h. It does not while the due is batched and the head lists two sources, nor within an hour of the first head it sees with fewer. A device that holds a REMOVE generation the head has not recorded counts the hour from when it first held it.

**Status.** `EvsRepo.PathEpochStatus(refName)` returns `{Current, Sources, DueGeneration, DueBy, Class, State, PartsUploaded, PartCount}` with State one of `none`, `waiting_mapper`, `waiting_sources`, `building`, `uploading`, `committing`, `overdue`. `ur status` prints one line per ref whose State is not `none`: `<repo> <ref>: path epoch <cur> -> <due>, due <time> (<class>): <state>`.

**Errors.** `EVS_PATH_EPOCH_DUE` (a creation waited out its bound; retryable), and for a read, `ErrGkmKeyMissing` unchanged when the device does not yet hold the current epoch's generation. Neither is an alarm.

**Deposits and erasure.** A deposit, a CONSUME and an ERASE act on deposit and erasure refs, which declare epoch 1 and skip everything above. A CLOSURE writes a content ref and goes through the planner and the sender like any write.

### 9.3 Invariants and why they hold

**P1, no late token.** No request names `tp(X, e)` unless evs was already shown a token of X at or below e, or e is the head's current epoch as the sender verified it within `EpochFreshFor` and, on a blocking ref, the sender holds no immediate removal above it, or the ref has no head and e is the epoch 9.2.3 gives its creator. *Why.* A token goes out under the floor rule, the new-name rule or the rule for a ref with no head, and no other. Under the floor rule e is at or above a floor, and each kind of evidence that sets a floor is evs holding the token: it served the statement, leaf or row that contains it (E1, E2), it answered the request that carried it (E3), or it holds the push whose statement a writer's signed entry says wrote the path (E4). A holder of K_path_e holds every lower path key, so it could already test the token at the floor. A map is the same rule with `born` for the floor. The new-name rule is the second clause as written. A first push is the third (QD-632). On a ref that is no overlay it tokenizes every name under p, the newest REMOVE generation its creator holds; a holder dropped at REMOVE generation r' holds exactly the path keys below r', and every removal the creator knows of has r' at or below p, so none of them can test a token under p: no new ref's first names are tokenized under a removed key. On an overlay p is the base ref's current epoch: an inherited path's token under p is at or above its floor on the base, and a name new to the repo is sent only under `quiet` against the base's pressure, which is the second clause read on the base. evs holds what is committed to the same line: 5e takes a first push only in an epoch from 1 to its own generation, an overlay's only in its base's current epoch, and refuses a creation in a first push whose pin crosses a blocking removal above the epoch it names (9.2.6). Before the answer a ref's first push created in epoch 1 whatever its sender held, so in a repo past a removal every new branch showed evs its first names under a key the removed holder has, until the ref's first cut-over; `PathEpochTwin-NewRefAtOne` is that. Two things remain and are published: the `EpochFreshFor` window of 9.2.3, and a device that has not yet been told of a removal, which is §11.5's bound as it stands ("names created before the path epoch that drops it").

**P2, a conclusive read is the newest.** *Why.* A path's entry lives at an epoch at or above every floor any client holds for it: each kind of evidence dates from the path's placement there or earlier, and an entry only moves to newer epochs. So the sources a reader asks, those at or above its floor, include the entry's home, and evs's rule (the current entry, else the newest source's) returns it. A miss is taken as absence only when every listed source was asked, or the parent's table has no row for the name, and a standing path has a row (P6). The newest-version rule above the entry is §11.7's, and the window it reads holds only the current epoch (W1).

**P3, path-level CAS across epochs.** A push commits only on the newest version of each path it changes, and no creation lands on a path that stands. *Why.* A change to a standing path names the sources at or above its floor, so 5g reads the entry's home (P2). A creation with no floor was planned on a listing with no row for the name, so the path was absent at the plan's head; any creation since is in the push's own epoch, where 5g reads it, unless the epoch moved, and then the push is refused, its epoch becomes the floor, and the retoken names it as a source, where 5g reads whatever was created there. A first push needs its own clause (QD-632): it was planned on a ref that held nothing, in an epoch its sender chose, so it commits only as the push that creates the ref, is refused whole on a ref that has a head, sets no floor, and is planned again from listings (9.2.3, 9.2.6). `PathEpochTwin-StaleFirstPush` is the design without that clause: a creation over a file another creator made in a lower epoch, after a cut-over reached the epoch the stale push named.

**P4, statements are checked in their own epoch.** For every version, removal and delta a reader accepts, and every walked statement after it, the reader holds a proof under its own `tp(X, e)` for that statement's epoch that the statement does, or does not, change the path. *Why.* It is §11.9's reader row applied per epoch. The reader derives the token path itself, so evs cannot answer for another path; an inline list is checked without evs; a rooted one needs evs's adjacent-leaf proof, and a missing proof is asked for once and then refused. An honest writer names a path by its token in the statement's epoch, which 5e pins to the head's. So the rollback of 9.1 B is caught at statement 110, under `tp(X, 1)`.

**M1, a map cannot misdirect a read.** If a map moves X's entry under another name's token, a read of that name is served a version whose statement names `tp(X, e)`, not the reader's token for the name it asked, and P4 refuses it. A row the map sealed wrongly fails its AEAD or its token check and the listing is refused (§11.7's name row). A map can therefore withhold or break, which 9.5 recovers from, and never substitute.

**P5, sources drain.** Every entry a source holds is a marker or is named there by the newest committed map or its tail, so the copy's end LIST finds nothing else and the sources drop. *Why.* An entry could be left unnamed three ways. A map built on another epoch state would not know a source: the between fence refuses it. A path created after the map's source: the mapper covers creations through its base, and evs's tail check covers those after it, all of which the window holds. A path changed, removed or re-created since: the fold that wrote its current entry deleted the source copies its push named, and those are every copy there is, because no evidence can lift a writer's floor above a copy that still stands. A row is translated only after its child's move, deletes included, has finished, and a version's statement is at or below the epoch of the copy that holds it. The newest map names each remaining path from `born` up, which is at or below its row's epoch, so it names the path's home and the epoch its row is matched in. The model takes a move's two writes apart, so a copy killed or superseded between them is among what it checks.

**P6, one row per standing path.** A standing path has exactly one row in its parent's table, and a path that does not stand has none. *Why.* A creation adds one, after a listing showed none (P3). A removal drops the child's token in every epoch at or above the path's floor, which the row's own epoch is (E2). The copy turns a carried row into the current one in place, after the child's move.

**W1, the unfolded versions are the current epoch's.** A PATH_EPOCH's process folds every earlier version and commits `folded_through = v` (§11.7's when row (4)). So every window version above `folded_through`, and every delta above a table's `names_through` that is not yet folded, was committed after the newest cut-over.

**P7, a mapper costs time only.** Nothing a mapper does before its PATH_EPOCH commits is visible to any reader or writer: parts are objects no head names. A map whose state moved is refused by the fence, whose hash matches no stored bytes by MAP_PARTS, and whose source is gone by MAP_SOURCE, each leaving the head as it was. The job record makes every step repeatable.

**K.** A retoken's kept slot ids name the bytes the refused statement would have written, and that statement can never commit, so no slot is introduced by two committed pushes.

**The model.** `PathEpoch.tla` holds one ref whose paths are files under one directory that any client lists without a token, which is the root. It models keys and heads (a rotation, a device learning it, a head read), reads by the floor and new-name rules and lookups, plans, pushes with their fold, the 412 and the retoken, abandoning a plan, a mapper building from either kind of index and committing against the fence, the tail and the source slots, and the copy: each move as its two writes, the PUT of the current entry and the DELETE of the source copies, with any other step between them, then the row translation and the drop. A token is the pair (path, epoch), and `seen` is every pair a request showed evs. Its invariants are P1 (`NoLateToken`, `FloorsBacked`), P2 (`ReadsNewest`), P3 (`NoLostUpdate`), P5 (`NoneMissed`, `EntriesHome`) and P6 (`RowsLead`, `NoGhostRows`), with `TypeOK`. Every rotation in it is a REMOVE and immediate. TLC is the owner's jar, a nightly from master at d8fb231, through `.stack/tools/tlc`; `run-pathepoch.sh details-9 all` runs everything below and deletes each run's state directory as it ends.

A ref with no head (QD-632). The model's ref used to exist from the first state, in epoch 1 with no version, and a mapper could cut it over before its first push, which evs does not allow. With the constant `NewRef` the ref has no head until its first push commits: no path of it is read, no PATH_EPOCH commits, and the first push names its epoch, which the commit makes the head's. The creator names the newest generation it holds, every rotation here being a REMOVE, and sends its first names only while it holds none newer than the one it names. `PathEpochTwin-NewRefAtOne` is what landed before the answer, a first push that creates in epoch 1 whatever its sender holds: it breaks `NoLateToken` in a trace of six states (a rotation, the device learning it, a listing, the plan, the push). A device that has read no head of the ref sends no token in a read, and a creator knows the head its own push made. A push planned on no head is sent only while the ref still has none; `PathEpochTwin-StaleFirstPush` sends it to a ref that has since got a head, as any push is sent, and breaks `NoLostUpdate` in a trace of 13 states: one device plans the ref's first push in epoch 2, another creates the ref in epoch 1, a mapper cuts it over to epoch 2, and the first device's push, naming the head's epoch and no source, creates over the other's file. The model found that case in the design as this amendment first had it, which retokened a refused first push; 9.2.3 and 9.2.6 carry the rule that closes it. `PathEpochReach-NewRefLate` shows the design does create a ref above epoch 1. Every other configuration sets `NewRef` false and explores the graph it did. An overlay is not modeled: the model has one ref.

```text
configuration                          what it holds, and the result               distinct states   depth      time
PathEpoch.tla, the design (Twin none)
PathEpoch                              2 writers, 1 mapper, 1 cut-over, 6 versions
                                       pass, every invariant                            1,020,926      30       30 s
PathEpoch-Three                        1 writer, 1 mapper, 2 cut-overs, 7 versions
                                       pass, every invariant                              558,167      34       11 s
PathEpoch-Two                          2 paths, 1 writer, 1 mapper, 1 cut-over, 5 versions
                                       pass, every invariant                              178,282      27        3 s
PathEpoch-Mappers                      1 writer, 2 mappers, 2 cut-overs, 5 versions
                                       pass, every invariant                            5,921,003      34   2 min 2 s
PathEpoch-Pair                         2 writers, 1 mapper, 2 cut-overs, 5 versions
                                       pass, every invariant                           27,248,431      37 14 min 42 s
PathEpoch-NewRef                       a ref with no head (NewRef): 2 writers, 1 mapper, 2 rotations, 4 versions
                                       pass, every invariant                            9,547,324      35   4 min 3 s
PathEpoch-Wide                         2 paths, 2 writers, 2 mappers, 2 cut-overs, 9 versions; by simulation:
                                       1,400,000 traces of at most 80 steps from seed 9
                                       pass, every invariant         154,952,958 generated       80  7 min 34 s
PathEpoch.tla, one rule of the design broken
PathEpochTwin-SendAllSources           a read names every listed source (the landed tokenize; A)
                                       NoLateToken violated, a trace of 12 states             669      14        1 s
PathEpochTwin-MapAllSources            a map names every listed source (§11.6's map row; A)
                                       NoLateToken violated, a trace of 12 states           1,980      14        1 s
PathEpochTwin-StaleEpochSend           a new name sent on a head that is not fresh
                                       NoLateToken violated, a trace of 7 states              345       9        1 s
PathEpochTwin-NoNewNameRule            a new name sent by a device that holds the removal's generation (F)
                                       NoLateToken violated, a trace of 5 states               53       7        2 s
PathEpochTwin-NewRefAtOne              a ref's first push creates in epoch 1 whatever its sender holds (QD-632)
                                       NoLateToken violated, a trace of 7 states              128      13        2 s
PathEpochTwin-StaleFirstPush           a push planned on no head sent to a ref that has since got one (QD-632)
                                       NoLostUpdate violated, a trace of 13 states          9,179      16        3 s
PathEpochTwin-MissIsAbsent             a miss in the current epoch read as absence while sources stand
                                       ReadsNewest violated, a trace of 11 states           2,282      13        2 s
PathEpochTwin-BlindRetoken             a retoken that names no source (C)
                                       NoLostUpdate violated, a trace of 14 states         16,482      15        5 s
PathEpochTwin-NoBetweenFence           a PATH_EPOCH across another (D)
                                       NoneMissed violated, a trace of 12 states           10,832      13        5 s
PathEpochTwin-NoTailCheck              a PATH_EPOCH whose tail misses a creation
                                       NoneMissed violated, a trace of 8 states               396      12        4 s
PathEpochTwin-FoldKeepsSources         a fold that leaves the source copies (the landed fold; E)
                                       NoneMissed violated, a trace of 16 states           12,789      17        3 s
PathEpochTwin-RowsBeforeMoves          the copy translates rows before the children's moves
                                       RowsLead violated, a trace of 9 states                 242      10        1 s
PathEpochTwin-RemoveCurrentRowOnly     a removal that drops the current-epoch token alone (G)
                                       NoGhostRows violated, a trace of 12 states           1,171      14        3 s
PathEpoch.tla, a state the design must reach (the invariant denies it)
PathEpochReach-TwoCutOvers             a path created in epoch 1 standing in epoch 3 with the sources dropped
                                       NeverTwoCutOvers violated, a trace of 12 states      4,280      14        4 s
PathEpochReach-Retoken                 a refused push retokened with a source path
                                       NeverRetokened violated, a trace of 10 states        1,503      11        3 s
PathEpochReach-NewRefLate              a ref whose first push commits in an epoch above 1 (QD-632)
                                       NeverBornLate violated, a trace of 6 states            234       8        2 s
```

These are the runs of 2026-11-10 on the model with the ref's first push in it, every configuration run again. Every design run passes, and every twin and reach run ends on the one invariant its configuration names. The breadth-first runs are complete graphs; the largest kept 1,023 MB of state on disk. The five earlier breadth-first graphs are the graphs first recorded, state for state, since `NewRef` is false there; a trace's length and a depth move by a state between runs with several workers, and the simulation's count differs because the same seed draws its traces in another order once an action is added. `PathEpoch-Wide` is a random simulation, which keeps no state set and shows only that the traces it drew held every invariant. A twin's count is what TLC had explored when it met the violation, and with several workers it moves a little from run to run. The machine carried four build lanes throughout.

What the runs cover: a ref created by either of two writers in the epoch it names, with a rotation before, between and after their first pushes, the second creator dropped and planned again, and a cut-over of the new ref; and, as before, every interleaving, at those bounds, of two writers and a mapper over one and two cut-overs, with a push in flight across each cut-over, a refused push retokened or abandoned, a device that has and has not learned the new generation, a read on a stale head, two mappers at one generation and at two, a map built from either index, the copy's moves in any order against writes, a move left between its two writes while a push or a second cut-over lands, and the drop. What the model leaves out, and why each is safe:

```text
nested directories    a prefix's floor is at most its child's, and the prefix states (removed, fresh) are §11.6's as
                      landed, checked by FS-4 on the code
P4 and M1             sequential arguments about one reply, above; FS-10's cases cover them on the code
time                  a client's head read and the request after it are one step: the model is the design with
                      EpochFreshFor at zero, and StaleEpochSend is the design without it
the source below      MAP_SOURCE and the mapper's cover of (S, b] are a mapper's own diligence, not a fence: a miss is
the window            P5's alarm, and 9.9 puts the choice to the owner
parts, seals, leases  9.2.5 changes nothing in them but what is sealed again
and the block
overlays              the model has one ref; an overlay's first push takes its base's epoch by a check on one
                      head (9.2.6), and its paths' floors are the base's, which P1's argument covers
a first push naming   an honest creator names the newest generation it holds; one that names less is 5e's
less than it holds    crossing line, a sequential check on one push, tested on the code (9.6)
```

### 9.4 Cost

Sizes are computed from the wire formats at a path depth of 5 and names under 64 B; CPU figures are estimates to be replaced by 9.6's benchmarks.

**A map.** A move is 293 B with one source: 90 B of new token path, 94 B of source, 106 B of sealed name, 3 B of framing. Each further source named adds 94 B, and only a path that stood before a still-listed source's cut-over names one.

```text
live paths                  10,000        100,000 (a phone's bound)        1,000,000
map bytes                   2.9 MB        29 MB                            293 MB (280 MiB)
parts                       1             4 (14 at a phone's 2 MiB)        40
HMACs (p_new and cur)       ~21,000       ~210,000                         ~2.1 M
name seals                  10,000        100,000                          1,000,000
CPU, estimate               under 0.1 s   0.3 s desktop, 1 s phone         3 s desktop
local disk                  2.9 MB        29 MB                            293 MB, deleted at commit
upload at 20 Mbit/s         2 s           12 s                             2 min
evs writes                  1 create      4 to 14 creates                  40 creates of 7 MiB, P1
commit                      one PATH_EPOCH push: a LIST of the map's keys, one GET of part 1, at most one log page
```

A mapper holds one part in memory: 7 MiB on a desktop, and 2 MiB on a phone, which is inside R-EVS-14's 4 MiB. The 24 h a part may age and `MapMaxAge` of 20 h leave a mapper 20 h from its first part to its commit, against 2 min of upload, and 9.2.6's source rule means a busy ref no longer shortens that to its window. An immediate epoch is rare (a member's or a device's removal, a compromise), and batched ones are at most one a repo a day (§11.13), so a 1M-path ref uploads at most 293 MB a day and typically nothing.

**The copy** is §11.6's: three operations an entry, about 17 h for 1M entries at 50 a second and 6 h at 150. The fold's deletes add at most one DELETE per named source per changed path while sources stand, three at most, and each is one the copy then does not make, since its move finds the current entry and nothing to delete. A directory's removal adds a LIST per named source and a DELETE per child copy, as its markers already cost a LIST and a PUT per current child. Hashing the map as the copy reads it costs under a second for 280 MiB. The leaf fields add at most 6 B per folded version.

**A read while sources stand** costs what §11.6's costs row says: a HEAD per prefix and a GET per listed source asked. The floor rule asks fewer sources than the landed code, never more. New costs:

```text
a no-floor name          one listing per directory level not cached for the head version: a round and at most
                         448 KiB each, 13 KiB for a directory of 100 names; none on a mirror; none once the
                         directory has been listed at this head
a head not fresh         one head-only round before a new name's first read, within §11.9's 20-50 ms
a second round           only when a walked statement of an epoch the request did not name has a rooted change
                         list whose covering prefixes reach the path
request bytes            90 B per epoch named per path; at most 8 epochs; 46 KB for 64 paths at depth 5, and
                         295 KB at depth 32
history                  one more round per epoch boundary the walk crosses
```

A phone's catch-up budget (§11.9, 4 MiB) is untouched: a path's walk is the statements it already fetched.

**A retoken** costs CPU and the push's parts again, never its segments: for a 100,000-file import, 98 parts of about 300 KB each, 30 MB, against every segment a second time today. It reads the head once and no path.

**evs.** 5e's source rule adds at most one cached log-page GET, 70 KiB. The crossing refusal is one refusal fence write, as any recorded refusal is.

### 9.5 Failure modes and recovery

```text
what fails                                  what happens                                    recovery
a mapper dies building                      nothing was sent                                the next tick builds again
a mapper dies uploading                     parts and the job record are on disk            resume from the record; evs takes
                                                                                            equal bytes as success
a mapper dies between parts and commit      as above                                        replay, tail, push
the only eligible device is offline         creation waits on a blocking ref under an       another eligible device maps after
                                            immediate due; writers alarm after 1 h          MapperSpread; else the owner brings
                                                                                            a full-sync device up (ur status)
two mappers, one generation                 the second's PATH_EPOCH: 412 PATH_EPOCH         done; its parts are 2.2.5's
two mappers, two generations                the second: 409 MAP_SOURCE                      it maps again from the new state
a creation lands after the mapper's base    409 naming the paths                            a longer tail; then the block
the source left the window                  one log-page read; the map stands               none needed
a part is missing, or past 24 h             409 MAP_PARTS, recorded                         upload again, else build again
three sources stand                         412 EPOCH_SOURCES_FULL; creation blocked        the copy drains; §19.8's liability
a map that omits or mis-seals paths         the copy alarms on what no move named and       a mapper maps again to a newer
                                            keeps the source; a listing with a bad row is   generation (ur keys rotate gives
                                            refused, tamper                                 one), which seals every row afresh
a map whose bytes do not match its hash     the copy moves nothing and alarms               as above
a push in flight across a cut-over          412 PATH_EPOCH                                  retoken (9.2.5)
a retoken meets a second cut-over           412 PATH_EPOCH again                            retoken again, to PushRebuildCount
a writer without the new generation yet     ErrGkmKeyMissing, or 412 GATE_CLOSED            gkm delivers; EnsureWritable
a reader's head is an epoch behind          the reply's head differs: nothing is trusted    pin it, ask again
a reader lost its records                   paths are never-read again: no floor            lookups; §11.9's trusts row
a fold dies between its PUT and DELETE      the range is not folded                         the next fold deletes
the copy dies between its PUT and DELETE    a source copy below a newer one                 the copy resumes; superseded, the
                                                                                            next map names it (P5)
evs serves a stale or wrong epoch state     tokens for an epoch evs does not list are not   the reader retries on the verified
                                            read; a wrong state fails the head's chain      head; a fork is head_alarm
evs withholds a row or an entry             a never-read path reads absent (§11.9's         a replaying peer's HeadCheck and the
                                            trusts row); a read one fails its record        record's rule alarm, as today
evs asks for an older epoch's token         the client has no rule that sends one below     none: 9.2.3 has no such path
                                            a floor
a first push names an epoch below a         412 PATH_EPOCH_DUE, recorded in the placeholder;  the creator names the generation
blocking removal its own pin covers         no head and no due is written                   crossed and sends again
a first push names an epoch above its       412 PATH_EPOCH, final                           the epoch is read again by 9.2.3
generation, or an overlay's names another                                                   and the push sent under it: the
than its base ref's current one                                                             ref still holds nothing
two creators' first pushes race             one creates the ref; the other answers 409      it reads the head and plans again
                                            (BASE_STALE, or non-fast-forward in git mode)   from listings; never retokened
                                            whatever epoch it named, and sets no floor
an overlay's base ref is under an           its creator waits (ErrEvsPathEpochDue), and evs  a mapper cuts the base over, and
immediate removal                           answers a creating first push 412               the creator names its new epoch
                                            PATH_EPOCH_DUE
an entry folded with no leaf place          the reply carries the statement alone           the reader names that epoch and
                                                                                            asks again, one more round
```

Two rows can need a person: no eligible device coming back, and a map that omits or mis-seals paths. Both are alarmed.

### 9.6 The test plan

Every test is a top-level `func TestXxx`, deterministic, on fakes with barriers. Barriers are named `evs.epoch.<point>` and listed in `evsservice/barriers.go` or, for the client, beside `evs_epoch.go`.

**Floors and rules (`evs_epoch_test.go`).** A table over the four evidence kinds: each lowers the floor to its epoch and nothing else does (a transport failure, an unverified reply, a row that fails its token check). The floor rule and the new-name rule as tables over (floor, cur, sources, pressure, head age). `pressure` against evs's own classification on the same states, so the two never differ. A lost record: the next read looks the name up.

**The capture (FS-4's "no late token").** A fake evs records every token path of every request, by epoch. A scripted run over three epochs with two devices, a removed third and a mapper: names created before, between and after each cut-over, read, listed, changed, removed, re-created and renamed, with a push in flight across each cut-over and a reader on a stale head. The check is P1 itself: for every recorded token path under a non-current epoch, an earlier record of the same path's token at or below that epoch. The same run with `tokenize` as landed fails it, which the test asserts once under a hook.

**Reads (`evs_epoch_read_test.go`, `evsservice/read_test.go`).** 9.1 B's three cases end to end on T2: a file last written before the cut-over by a rooted push reads and verifies, moved or not; a reader pinned before the cut-over refuses a rollback across it, with the change at an inline and at a rooted statement; an unmoved directory lists, its rows opened under `entry_epoch`. A carried row and an untagged one in one table. A request naming no current-epoch path: `stale_epoch`, and the retry. A rooted statement of an epoch the request did not name: the second round, once; evs still silent: refused. A proof whose leaf names another path: refused. A map that moves X under Y's token: the read of Y refused (M1). History across two cut-overs, by folded versions and by `commit_version`, with E4's check and a statement of another push refused.

**Writes and the retoken (`evs_plan_test.go`, `evs_push_test.go`).** 9.1 C: w's creation after v's, across the cut-over, answers 409 and v's file stands; under a hook that forgets the lowered floor it commits, which the test asserts. G: a removal while its row is carried drops the row, and the name is created again with one row. F: a device holding the removal's generation plans a creation on a blocking ref: nothing is sent, `ErrEvsPathEpochDue`; on a mailbox ref it creates. A ref with no head (QD-632): in a repo whose newest REMOVE generation is 3 of 5, a creator's first push names epoch 3, sends no read first and no source path, and the capture shows no token of the ref under an epoch below 3; with no REMOVE generation it names 1; an overlay's creator names its base ref's current epoch, and waits while the base ref's pressure is immediate when the push holds a name new to the repo; a first push that meets a head is dropped, sets no floor and is planned again from the listing, and one whose base ref's epoch moved is sent again under the new epoch. K: a retoken keeps segment ids, receipts and slot ids, and the fake counts one upload; a CLOSURE across a cut-over charges once. A retoken of a 2,000-entry push in parts. A retoken whose generation the gate refuses goes to the rebuild.

**evs (`evsservice/fold_test.go`, `epoch_test.go`, `epoch_copy_test.go`, `check_test.go`).** The fold deletes each named source copy after its PUT, on the run that wrote and on a run that finds the entry written (a kill between, by barrier); a directory's removal empties the named sources below it; 9.1 E end to end, the superseding copy's end LIST finding nothing, and with the delete off, an alarm. The between fence: D's two mappers, the second 409 MAP_SOURCE, then mapping again and committing. A source below the window by one page commits; by more, 409. A crossing push that creates: 412 PATH_EPOCH_DUE, recorded, the head's due set, a retry answered from the record; one that only modifies commits and records the due. A first push (QD-632), each case with its twin: naming its newest REMOVE generation it commits, and the head starts at that epoch with no source and no due; naming epoch 1 across a blocking removal it answers 412 PATH_EPOCH_DUE, recorded, with no head and no due written, and the same push naming the crossed generation commits; across a batched removal it commits and the head records the due; naming an epoch above its generation, 412 PATH_EPOCH; an overlay's in its base ref's current epoch commits, in any other 412 PATH_EPOCH; a deposit ref's in any epoch but 1, 412 PATH_EPOCH; a push with base version 0 on a ref that has a head, 409 before its epoch is compared, in both modes; `PathEpochTwin-StaleFirstPush`'s schedule end to end (a second creator's first push arriving after the first creator's ref was cut over to the epoch it names: refused, and under a hook that lets it through it creates over the standing file, which the test asserts); the landed exemption's test (a creating first push in epoch 1 past a removal commits) turned into the refusal. The copy refuses a map with a swapped part and one out of order. Leaf places are written by a fold and kept by a carry, for a rooted list and for an inline one (part 0, the index plus 1; QD-633). After a cut-over, with the request naming no token path in the older epoch: a directory whose newest delta an inline push of that epoch wrote, an elided version of an inline push, and a removal marker of one, each served in one round with its change; an entry whose place is not recorded answered with the statement alone.

**The mapper (`evs_epoch_map_test.go`), FS-4's mapper half.** Paths inserted, deleted and renamed after the map's enumeration reach the tail, removed ones included. A kill after half the parts: the restart uploads the rest, byte-equal, and commits. A kill before the job record: nothing on evs. A map from a replayed index and from a listed one for the same tree name the same moves but for sources between `born` and the row's epoch. Steady creation: two tail refusals, the block, the commit inside it. Three sources: the job waits and commits after the drop. A batched due with two sources: no map is built. The mapper offline: `epoch_overdue` one hour past due, not during the deferral, not within an hour of its end. `MapMaxAge`, a newer REMOVE generation and a lost eligibility each abandon.

**The root (`EVS1-M2-46`'s tests).** A top-level creation's row; List of the root; the root's move last; a top-level name looked up with no token of it sent.

**Models.** `run-pathepoch.sh details-9 all` in the model suite beside `run-settle.sh`; the thirteen twins join `mutants/mutants.yml` when the code lands, each mapped to the test above that fails without its rule (`NewRefAtOne` and `StaleFirstPush` to the first-push rows).

**Benchmarks, reported and not gated in the draft phase.** A 1M-path map built and hashed (target 10 s on the desktop leg); a 100,000-path map on the mobile leg under 4 MiB of working set; a read with a lookup at depth 5; a retoken of a 100,000-entry plan.

Left to the review phase: FS-4's exhaustive schedules on T3, the capture under random schedules, and mutation sweeps.

### 9.7 Implementation notes, task by task

The held tasks need landed code changed first, and EVS1-M2-28 as planned is two tasks' work. `.stack/plan/proposals/details-9-tasks.md` gives the four new tasks and the changed one in the plan's format. They are numbered after EVS1's last M2 task; the orchestrator may number them otherwise. All are the data lane's.

**New: EVS1-M2-44, path-epoch fences on evs** (sidecar; M). 9.2.6's fold, 5e and copy changes.
- `evsservice/fold.go`: after `foldRun.writePath` settles a path (its PUT, or `merged.changed` false), delete the listed source copies its events' source paths name; `foldPath.sourcePaths` today returns the first change's, and must return every change's in the range. A directory removal's LIST and deletes go beside `markBelow`, in a new `evsservice/fold_sources.go`. Each delete is paid as the fold's entry writes are, through `self.acquire`, carries `self.staleDeadline`, and counts in a new `EvsFoldResult.SourceDeleteCount`. The run returns only after they answer, so `folded_through` cannot rise over a range whose deletes are outstanding. Barriers `evs.fold.source_delete.before` and `.after`.
- `evsservice/epoch_commit.go`: `pathEpochRules` reads the source statement through `self.pushes` when the window holds S; `baseChainAt` answers nil below the window, so for an older S a new `sourceBelowWindow` reads log page ⌊S/64⌋ (`EvsSettings.MapSourcePageCount`, default 1), recomputes C_S from its `first_chain` and returns the statement. Then the chain check, then the between fence against `EvsHeadCurrentEpoch(head)`. `readPathEpoch` is unchanged: it already scans only the window. The refusal reasons stay `EvsCheckReasonMapSource` and `EvsCheckReasonTailMissing`.
- `evsservice/check_cas.go` and `refuse.go`: step 4 already computes `self.due` (`push_step4.go`, from `pathEpochDueOver`) and the commit applies it (`push_commit.go`). `PushView` gains `CrossingDue *pathEpochDue` set from it; `CheckPathEpoch` refuses a creating push when `CrossingDue.blocks`, with `EvsCheckReasonPathEpochDue`, as a recorded refusal; and `pushAttempt.record` applies `applyPathEpochDue` to the head its refusal fence writes when the attempt holds a due. The classification moves to a root function, `EvsClassifyPathEpochDue(holdersShrunkAt, fromAuthVersion uint64) bool` in `evs_epoch.go`, which `pathEpochDueOver` and the client's `pressure` both call.
- `evsservice/epoch_copy.go`: `loadMoves` hashes the parts in order and checks 9.2.2's order; a mismatch returns a new `ErrEvsCopyMapInvalid`, alarmed, with no move made.
- `protocol/evs.proto`: `EVS_REFUSAL_MAP_SOURCE = 75`, final, which `refusal_codes.go` gives `EvsCheckReasonMapSource` in place of MAP_PARTS and `evs_refusal.go` a typed error. It is this task's one wire change.
- Tests: 9.6's evs row.

**New: EVS1-M2-45, reads across path epochs on evs** (sidecar; M). 9.2.2's fields and 9.2.4's route.
- `protocol/evs.proto` and `evs.pb.go`, `protocol/EVS-FORMAT.md` (9.2.2's rules, the map's order among them), `testdata/evs/` vectors, `protocol/evs_descriptor_test.go`.
- `evsservice/read.go`: `newReadAttempt` matches token paths by epoch into `EvsPathTokens` (`sources.go`: `Current` is the one whose epoch is the head's current; a new `ByEpoch map[uint64]sidecar.EvsTokenPath` holds all), and answers `stale_epoch` when there is none; it no longer fails the request for "a path with no current token path". `pathReply` sets `entry_epoch` from `EvsPathRead.SourceEpoch`. `versionReply`, `deltaReply` and `attachStatement` take the leaf place whenever the statement's epoch is not the head's current one, and `readPushes` (`read_proof.go`) gains `entryVersionAt(push, part, index)` beside `entryVersionOf`; `inclusionProof(push, part, index)` is used as it is. `absences` walks each statement in its own epoch: `tokens.ByEpoch[e(w)]`, skipping the statement when absent. `olderVersion` honors `commit_version`.
- `evsservice/fold.go`: `mergeFoldEvents` records `leaf_part` and `leaf_index` for each folded version, the marker and `names_leaf_*`; `carryEvsIndexEntry` and the copy's `translated` already clone the versions and keep them.
- `metadata_list.yml`'s evs-11 takes 9.8's words in the same change (I-18), with `check/`'s metadata test.
- Tests: 9.6's reads row, server half.

**New: EVS1-M2-46, the root directory's table** (sidecar; M). Question evs1-m2-24-root-directory-names, option 1, as 9.2.8 extends it. `evs_token.go`: `ParseEvsChangedTokenPath` takes the empty path for a directory delta only. `evsservice/entry.go`: the root's key `idx/<repo>/<ref>/<p>.e`. `evsservice/fold.go`, `check_cas.go` (5g's directory bound at the root), `evs_digest.go` (the empty path's digest rule: a root delta sets the two bits of `SHA-256("UR evs digest")`), `evsservice/read.go`. Client: `evs_read.go` (`evsPathNames("")` is the root), `evs_list.go`, `evs_directory.go` (a top-level creation or removal adds to the root's delta), `evs_export_file.go` (file-mode export no longer refuses). `evs_payload.go`: `checkEvsPathMove` takes the root's move (an empty path in each epoch, no sealed name). `evsservice/epoch_copy.go` needs only that: the empty path sorts first, so the root moves last. Tests: 9.6's root row, and EVS1-M2-24's refused cases turned into passes.

**EVS1-M2-28, client path epochs: floors, reads, writes and the retoken** (held; L; scope changed). It keeps §11.6's read, leases and alarm rows and re-tokenizing, and loses the mapper, the block and the tail to EVS1-M2-47. Needs EVS1-M2-45 and EVS1-M2-46, and EVS1-M2-44 for its end-to-end tests. Build 9.2.3, 9.2.4, 9.2.5 and 9.2.8's alarm, status and errors:
- `evs_epoch.go` (EVS1-M2-44 starts the file with `EvsClassifyPathEpochDue`): floors and the evidence kinds; the two rules as `evsEpochTokens(ctx, ref, path, need) (epochs []uint64, lookup bool, err error)`; `pressure`; `EvsRepo.PathEpochStatus`; the alarm. `evs_epoch_read.go` (new): `lookup`, the listing cache, the read loop.
- Landed code that changes. `evs_read.go`: `tokenize` goes; `read` and `readRound` become 9.2.4's loop, the head-only round also when the epoch state is older than `EpochFreshFor` and a path has no floor; a reply whose head has another epoch state is pinned and the paths asked again (today it pins only after the paths verify). `evs_proof.go`: `VerifyPath` and `verifyUnchangedSince` take `func(epoch uint64) (EvsTokenPath, error)` in place of one token path, check each statement under its own epoch, and return the epochs they need more of; `evsChangeOf` compares the leaf with the token path of the statement's epoch. `evs_list.go`: untagged rows open under `entry_epoch`. `evs_history.go`: `commit_version` and E4. `evs_pin_store.go`: `EvsReadRecord.Floor` and `PinEpoch`, written by `RaiseReadRecords`; a stored record without them reads as no floor. `evs_plan.go`: the `ErrEvsWriteNotBuilt` refusal at line 247 and `errEvsPlanEpochMoved`'s source clause go; source paths and `pressure` come in; `EvsWritePlan.Retoken(head)`. `evs_directory.go`: `evsChildChange` carries the child's token per epoch for a removal. `evs_push.go`, `evs_write.go`: PATH_EPOCH leaves `evsRebuildCodes` for the retoken branch; the wait for PATH_EPOCH_DUE. `evs_payload.go`: section 12's builder if the planner has none. `evs_settings.go`: 9.2.2's client settings. `evs_refusal.go`: `EVS_PATH_EPOCH_DUE`.
- Traps: a floor is lowered only after evs answers (E3), never when a request is built; `tp(X, e)` for a proof is always computed locally, never read from a reply; the head-only round is skipped only for paths that have a floor; a retoken reuses a receipt only under 22 h old; a deposit or erasure ref bypasses all of it (`evsEpochExempt(refKind)`); on a ref whose kind does not block, `pressure` never holds a creation.
- Tests: 9.6's floors, capture, reads (client half) and writes rows.

**New: EVS1-M2-47, the path-epoch mapper** (sidecar; L). Needs EVS1-M2-28, EVS1-M2-44, EVS1-M2-46 and EVS1-M2-16's routes. Build 9.2.7 and the map and tail rules of 9.2.2: `evs_epoch_map.go` (the job, build, upload, commit, the block), `evs_epoch_index.go` (`EvsNameIndex`, `EvsIndexedPath`, `evsListedNameIndex`, and `EvsBornJournal`, a helper a replaying mirror feeds), `evs_epoch_map_test.go`, and `sidecartest/fake_name_index.go`. `evs_component.go` runs the tick on each verified head, each PATH_EPOCH hint and a timer of `MapperSpread`, reading gkm's newest generation at each. The job directory is the evs component's sealed directory. EVS1-M2-33 and EVS1-M2-35 register the local tier's replayed index when they land (section 8); until then a desktop maps through the listed index. Traps: the job record is durable before the first upload; parts are sent from disk, never built twice; p_new is the newest generation held, never the due one; a tail holds removed creations too; the block is asked only after `MapTailRefusalCount` refusals and 10 min past `due_by_ms`; a batched due builds nothing while two sources stand. Tests: 9.6's mapper row.

**EVS1-M2-29, deposits, Consume and read receipts** (held; M; unchanged in scope). A deposit ref holds random ids under no path key and stays at epoch 1: `Deposit`, `Consume` and the receipt gate build their pushes with `path_epoch` 1, no source paths, no floors and no lookups, through the sender's `evsEpochExempt` branch, and none of them can meet 412 PATH_EPOCH or PATH_EPOCH_DUE (evs records no due there and refuses a PATH_EPOCH with 409 REF_MODE; plan-EVS1-epoch-kinds #2). Its rule that a deposit rebuilt for a newer drop key draws new slot ids stands: that is a re-seal, not a retoken. The only waits a deposit has are its own (`ErrGkmWait`, BASE_STALE). What a reader does with a consumed deposit, writing `m/` entries on the mailbox's shared ref, is an ordinary write under 9.2.5 on a ref that never blocks.

**EVS1-M2-30, erasure on the client** (held; M; one rule changed). ERASE pushes act on the erasure ref and declare epoch 1, as above. A CLOSURE writes the content ref through `Write`'s planner with the forced checkpoint, so it follows 9.2.5: its paths stand and have floors, and a CLOSURE refused 412 PATH_EPOCH is retokened with its segments, receipts and slot ids kept, so the closure upload is charged once; the trap "closure uploads count against the eraser's own allowance" needs no second 429 wait for a cut-over. Reconcile is unchanged in rule and gains one case: a refused CLOSURE is not "a duplicate CLOSURE's 409". evs's state shows no CLOSURE for it, and the resuming device builds it again from evs's state as for any unfinished pair. The erased list's (slot id, key index) pairs do not depend on tokens.

**New after the owner's answers: EVS1-M2-50, a ref's first epoch, inline leaf places and the head's index_epoch** (sidecar; M; `.stack/plan/proposals/owner-answers-tasks.md`). It changes what EVS1-M2-28, EVS1-M2-39, EVS1-M2-44 and EVS1-M2-45 landed as drafts, and needs nothing else.
- A ref's first push on evs (QD-632; 9.2.6). `evsservice/check_cas.go`: `CheckPathEpoch` on a ref with no head takes the first-push rule in place of `current := 1` and of the return that exempts it from the crossing creation, and on a ref that has a head refuses a push whose base version is 0 before it compares epochs (`EvsCheckReasonBaseStale`, or the non-fast-forward reason in git mode). `evsservice/epoch_commit.go`: `pathEpochDueOver` counts from the push's own epoch on a ref with no head (today `max(head generation, head epoch)`, which is 1 there). `evsservice/push_step4.go`, `versions.go` and `check.go`: for an overlay's first push the view carries the current epoch and the block state of the base ref's head, read in step 4 beside the base versions `OverlayChains.BaseVersions` reads; the base itself comes from the creating push's payload section 16, which EVS1-M2-48 lands, so the overlay line is built on it and fails closed (412 PATH_EPOCH) until then. `evsservice/push_commit.go` already starts a head at the push's `path_epoch` and applies a due, and `refuse.go` already writes no due on a head at version 0: both stand and gain tests.
- A ref's first push on the client (9.2.3). `evs_epoch_read.go`: a new `firstEpoch` beside `pressure`, which walks the same generations, and `pressure`'s return of none for a ref with no head goes, since an overlay's creator is held by its base ref's pressure. `evs_plan.go`: a plan on a ref with no head names that epoch (today `evsCurrentEpoch(head.GetPathEpoch())`, which is 1) and reads no path. `evs_push.go`: a first push that meets a head is dropped and planned again, never retokened, and lowers no floor; one refused 412 PATH_EPOCH on a ref that still has no head is sent again under the epoch read again. EVS1-M2-34's `PlanGitUpdate` (held) names a new git-mode ref's epoch through the same function.
- Inline leaf places (QD-633; 9.2.2, 9.2.4). `evsservice/fold.go`: `leafPlacesAt` returns part 0 and the index plus 1 for an inline list, where it returns no place today. `evsservice/read.go` and `read_proof.go`: `locate` and `entryVersionIn` take an inline list's change by its place, and `statementAlone` is left for a place not recorded; `inlineEntryVersionEliding`'s match by elided bytes stays for those entries.
- The head's index_epoch (QD-640). `testdata/evs/reserved_numbers.yml`: `EvsHeadSummary.index_epoch` moves to `ignored` and `EvsHead.index_epoch` to `kept`; `testdata/evs/format2_refusals.json`: the `unswept` row becomes a reader row; `protocol/evs_reserved_test.go` and `sidecartest/evs_format2_refusal_test.go` read both. No other code changes.
- Tests: 9.6's first-push and inline rows.

**Order.** EVS1-M2-45, EVS1-M2-44 and EVS1-M2-46 in any order; then EVS1-M2-28; then EVS1-M2-47, EVS1-M2-29 and EVS1-M2-30 in any order. EVS1-M2-29 and EVS1-M2-30 need of EVS1-M2-28 only the sender's exempt branch and the retoken, which land in its first commit. EVS1-M2-50 follows EVS1-M2-28 and comes before EVS1-M2-34, which creates refs through it; its overlay line follows EVS1-M2-48. EVS1-M2-47, landed as a draft, is not changed: a mapper does nothing on a ref with no head.

**Other landed code this section touches by name:** `evsservice/fold.go`, `epoch_commit.go`, `check_cas.go`, `refuse.go`, `epoch_copy.go`, `read.go`, `read_proof.go`, `sources.go`, `entry.go` (EVS1-M2-44 to -46); `evs_read.go`, `evs_proof.go`, `evs_list.go`, `evs_history.go`, `evs_pin_store.go`, `evs_plan.go`, `evs_directory.go`, `evs_push.go`, `evs_write.go`, `evs_payload.go`, `evs_settings.go`, `evs_refusal.go`, `evs_token.go`, `evs_digest.go`, `evs_export_file.go`, `evs_component.go` (EVS1-M2-28, -46, -47); `protocol/evs.proto`, `protocol/EVS-FORMAT.md`, `metadata_list.yml` (EVS1-M2-45). `evs_subscribe.go` does not change. EVS1-M2-41's FS-4 schedules gain 9.6's cases.

### 9.8 Proposed DESIGN.md text

For a design-records track. Each item replaces the words it quotes and leaves the rest of its row.

**§11.5, the token leak bound.** After "each landing when a mapper commits (writers alarm an hour past due, not while such an epoch waits)": "and the token of a name first sent within 5 s of a cut-over, which can reach the server under the epoch just left (11.6's read row)".

**§11.6, path epochs' first sentence and the due row (QD-632).** For "1 at creation": "at a ref's creation the epoch its first push names: the newest REMOVE generation its creator holds, 1 when there is none; an overlay's, its base ref's current epoch; a deposit or erasure ref's, 1 for life". Add to the due row: "a ref's first push is held to the same rule from the epoch it names: evs takes it in an epoch from 1 to its own generation (an overlay's in its base ref's current epoch), starts the head there with no source, and refuses a creation in it across a removal that would block, so no ref's first names are tokenized under a removed key".

**§11.6, the due row.** For "the first commit whose generation pin crosses a REMOVE generation": "the first push whose generation pin crosses a REMOVE generation, at its commit, or, when it creates a path that the due blocks, at its refusal (412 PATH_EPOCH_DUE, recorded, the refusal's fence writing the due)". After "then gets 412 PATH_EPOCH_DUE until the epoch lands": "; a client that holds such a generation sends no new name under the older epoch, in a read or a push, and waits the same way".

**§11.6, the map row.** For "per live path, its token path in p_new, in the current epoch and in every source the head lists, and its name re-sealed for the new parent and child tokens": "per live path, the root included, its token path in p_new, in the current epoch and in each listed source at or above the epoch its standing creation committed in, or its row's (the server was shown its token there; a source below it never held the path), and its name re-sealed for the new parent and child tokens; moves ascend by new token path within and across parts". For "keys name the map, so a mapper whose source left the window, or that finds another's map abandoned, uploads a fresh one": "keys name the map; a mapper keeps its built parts and a job record on disk and resumes an interrupted upload from them, and builds a fresh map only when its PATH_EPOCH answers MAP_SOURCE or its oldest part passes 20 h".

**§11.6, the tail row.** For "paths that window versions after the map's source create get moves like the map's, which the mapper builds from those pushes": "paths that versions after the map's source create, through the PATH_EPOCH push's base, get moves like the map's, removed ones included, which the mapper builds from those pushes". For "and evs checks every token path those versions create": "and evs checks every token path that the versions the window holds after the source create".

**§11.6, the commit row.** For "its source version is in the window with a matching chain": "its source version is at or below the head's, with a matching chain (from the window, else from that version's log page), the epoch its statement declares is the head's current one, so no PATH_EPOCH committed after it (else 409 MAP_SOURCE)".

**§11.6, the copy row.** After "one taskworker job per ref, for the newest map and its tail only": ", its parts hashed against the map's hash and checked for order as they are read, a mismatch moving nothing and alarming".

**§11.6, the read row**, whole:

```text
read     a client keeps, per path, the lowest epoch in which it holds evidence the server was shown the path's
         token (its floor): a verified version, removal or row naming it there, a request of its own that evs
         answered, or the push a verified version names as its predecessor; it sends the path's token path in the
         current epoch, in each listed source at or above the floor, and in any other epoch at or above it whose
         statements it needs proofs under; a path with no floor is a new name: its token goes only under the
         current epoch, on a head verified within 5 s, never in a read while sources stand, and on a ref whose
         creation an immediate due blocks never while the client holds that removal's generation; such a name is
         looked up through its parent's table, from the root, which has no token; while sources stand, evs also
         HEADs in the same round a path's prefixes' current entries, whose state (11.7) rides in object metadata,
         each settled by 11.7's rule: under a removed prefix the path is absent, and under a fresh one too unless
         its own current entry is fresh; else evs uses the current entry, else the newest source's, and if every
         GET of the path returned 404 it GETs the current one again, since a fold and the copy PUT it before
         deleting a source copy; the reply names the epoch that served (entry_epoch); changes name their source
         paths by the floor (the payload's source paths), and a delta removing a child lists its token in the
         current epoch and each such source, so a fold drops a carried row too; a push refused 412 PATH_EPOCH
         makes its epoch the floor of every path it named and is re-tokenized on the new head with every sealed
         byte, receipt and slot id kept; readers check a carried row under its epoch's tokens and AAD, an
         untagged row under the serving epoch's, and every statement under the path's token in that statement's
         own epoch
```

**§11.6, the object key row.** For "Slot ids are 16 random bytes drawn per statement: a push rebuilt after a refusal draws new ones, and a retry of the same statement keeps them (11.8)": "Slot ids are 16 random bytes drawn when a push is sealed: a push sealed again after a refusal draws new ones, and a retry of the same statement and a push re-tokenized after 412 PATH_EPOCH keep them (11.8)".

**§11.6, the protos.** `EvsReadPath`, `EvsReadPathReply`, `EvsIndexVersion`, `EvsRemovalMarker` and `EvsIndexEntry` take 9.2.2's fields, in §11.6 or §11.9 wherever each is declared; a leaf place is recorded for an inline list too, part 0 and the index plus 1, and `leaf_index` 0 means not recorded (QD-633).

**§11.6, the kinds row (QD-640).** Move "EvsHead's index_epoch" out of what format-1 code refuses in use, to stand beside the window bits: "format-1 code reads past a head's `index_epoch` and its summary's, carrying the head's forward in its own writes".

**§11.7, the epochs row.** After "rows already carried keeping theirs until the copy translates them (11.6)": "; once the current entry holds the change, the fold deletes the listed source copies the change's source paths name, and under a removed directory every key below it in those sources, its range folded only when they have answered".

**§11.7, the holds row.** After "per file up to four folded EvsEntryVersions with their push id and commit version u": ", each with the place of its change in its statement's list".

**§11.8, step 5e.** For "its source binding valid, its tail covering every later creation (else 409 with the paths)": "its source at or below the head with a matching chain and of the head's current epoch (else 409 MAP_SOURCE), its tail covering every creation the window holds after it (else 409 with the paths)". After "before block_until_ms -> 412 PATH_EPOCH_DUE": "; a creation in a push whose own pin crosses a due that would block -> 412 PATH_EPOCH_DUE, recorded with the due". For the first row's "1 for a ref with no head" (QD-632): "on a ref with no head, an epoch p with 1 <= p <= the push's generation, which becomes the head's current epoch with no source; an overlay's, its base ref's current epoch; a deposit or erasure ref's, 1; the crossing rule counts from p".

**§11.5, the token leak bound (QD-632).** The bound needs no clause for a new ref: with the first-push rule above, a new ref's first names are tokenized under no removed key.

**§11.9, the request row.** For "each with its token path in the current epoch and in each listed source that may hold it (11.6)": "each with its token path in the current epoch and in the other epochs 11.6's read row allows, at most 8, matched by epoch". **The reply row.** After "with the statement that wrote it (when not among those returned) and its Merkle proof": ", found by the version's recorded place when its statement is of an older epoch,". After "the adjacent-leaf proofs (11.6's order) that neither the path nor a prefix holding it is among its changes": ", for statements of each epoch the request named the path in". **The reader row.** After "that no statement after the version's own changes the path, or a prefix holding it, again": ", each statement checked under the path's token path in its own epoch, which the reader derives, asking once more for an epoch it did not name".

**§11.20.** `EvsNameIndex`, `EvsRepo.PathEpochStatus`, `EVS_PATH_EPOCH_DUE`, and the refusal 409 MAP_SOURCE beside MAP_PARTS.

**§2.8 and `metadata_list.yml`.** evs-11's sees, after "each entry's up to four committed versions, folded from committed pushes": ", each with the place of its change in its own statement's list". evs-11's ttl, for "no source-epoch token of a later name reaching the server (§11.6)": "no source-epoch token of a later name reaching the server but one first sent within 5 s of the cut-over (§11.6)". The place is a fact the push record already shows the server; no row gains a value it could not compute.

**§22, FS-4 (QD-632, QD-633).** It also gains: "a ref created after a removal starts in the removal's epoch, and its first push naming an older one is refused when it creates; a directory last changed by an inline push of an older epoch is read in one round after a cut-over".

**§22, FS-4.** Its mapper and reader half gains: "two mappers at two generations from one head, the second refused MAP_SOURCE and mapping again; a path removed and re-created while its copy is superseded, the next copy's LIST finding nothing; a creation refused 412 PATH_EPOCH that would land on a file created in the epoch it left, answering 409; a reader pinned before a cut-over refusing a rollback across it; a capture showing no token under a source epoch that was not sent at or below it before".

**Plan.** EVS1-M2-28's entry takes `details-9-tasks.md`'s lines; EVS1-M2-44 to EVS1-M2-47 are added; EVS1-M2-29 and EVS1-M2-30 keep their entries with 9.7's notes; EVS1-M2-50 is added from `owner-answers-tasks.md`.

### 9.9 Owner questions

This section was designed on the recommendation of each, and the owner answered all of them on 2026-11-10. Each answer is given after its question, with its ledger id.

**Where the root's names live (`details-9-root-names.md`, restating `evs1-m2-24-root-directory-names`).** Lookups, listings and maps all start at the root, which today has no table. Options: (1) the root is a directory with the empty token path, its entry `idx/<repo>/<ref>/<p>.e`, moved last by the copy: a format rule, the digest's empty-path rule and EVS1-M2-46; (2) top-level names ride in sealed metadata and readers fold them: no reader can then look a top-level name up without replaying, so every no-floor top-level read would send a token or fail, and a mapper must replay from version 1; (3) a reserved first component: a visible change to every path. Recommendation: (1). **Answered: QD-612, option 1**, the root is a directory with the empty token path; EVS1-M2-46 landed it.

**How evs finds an old version's change (`details-9-index-leaf.md`).** A version written in an older epoch sits under a token evs may never be sent again. Options: (1) the fold records each folded version's place in its statement's list (two small integers per version, a marker and a table), evs proves from the place, and the reader checks the leaf against its own token: EVS1-M2-45, and four words in evs-11; (2) the entry keeps the path's token path in each epoch it lived in: up to 512 B an epoch per entry, and a second copy of old tokens in `idx/`; (3) evs scans the statement's list for the entry's hash: a 100,000-change list read whole for one file; (4) the client sends the old token when evs asks: that lets a server ask for any name's token under a removed key, which is the leak itself. Recommendation: (1). **Answered: QD-611, option 1**, the fold records each folded version's leaf place; EVS1-M2-45 landed it. QD-633 (question `evs1-m2-45-inline-leaf-place`, option 1) extends it to inline lists, which 9.2.2 and 9.2.4 now carry.

**Whether the fold deletes source copies (`details-9-fold-deletes-sources.md`).** 9.1 E and its directory form leave entries in a source that no honest map names, and the source then never drains. Options: (1) the fold deletes the source copies its push named once the current entry stands, and empties the named sources below a removed directory: a change to the landed fold, at most three DELETEs a changed path while sources stand, each one the copy then skips; (2) the copy follows a leftover through the superseded maps to learn that a newer entry replaced it: the copy must keep and chain every map and tail since the oldest source, and a removed path still has no move to follow; (3) the copy deletes whatever its map does not name: then a map that omits a live path silently loses its index entry. Recommendation: (1). **Answered: QD-607, option 1**, the fold deletes the source copies its pushes named; EVS1-M2-44 landed it.

**The push that crosses a removal (`details-9-crossing-creation.md`).** §11.6 refuses creations once a due is recorded, and the commit that records it can itself create a path under the removed key. A client that holds the removal's generation is the only party that can keep the token from being sent, and 9.2.3 has it wait. Options for evs: (1) nothing more: an old or dishonest client's crossing creation commits, and the due is recorded only by a push that commits; (2) evs refuses a creation in the crossing push, 412 PATH_EPOCH_DUE, and records the due in the refusal's fence write: a dozen lines in 5e and the refuse path, creation stops at the first push across the removal whether or not it commits, and replaying readers can hold "no creation under an epoch below an immediate removal its pin covers" as a rule. Recommendation: (2). It cannot unsend the token; it keeps §11.6's sentence true of what is committed. **Answered: QD-609, option 2**, evs refuses the crossing creation and records the due; EVS1-M2-44 landed it. QD-632 (question `evs1-m2-44-new-ref-crossing`, option 2) removes the one exemption that build kept, a ref's first push: a new ref starts in the newest epoch its creator holds, and an overlay in its base ref's current epoch (9.2.3, 9.2.6).

**A map whose source left the window (`details-9-map-source-window.md`).** A map must be bound to a head still in the 64-to-127-version window when it commits, so on a ref committing once a second a map that takes two minutes to upload never commits. Options: (1) the source may be any version at or below the head, its chain read from one log page, evs checking the tail for the versions the window holds and the mapper answering for those between its source and its base, with the copy's end LIST and replaying readers catching a miss: one cached GET at the commit; (2) keep the window and have the mapper block every push, not only creations, while it uploads: a busy ref stops for minutes at each epoch; (3) evs checks every creation since the source from log pages and push records: thousands of reads inside one commit's 5 s. Recommendation: (1). The 24 h age of a part still bounds how stale a map can be. **Answered: QD-608, option 1**, a map's source may be older than the window; EVS1-M2-44 landed it.

**Who checks a whole map (`details-9-map-verifiers.md`).** evs stores parts under a hash it never computes, and §11.9 leaves the check to readers, for whom a 1M-path map is 293 MB. Options: (1) the copy job, which reads every part anyway, checks the hash and the order and moves nothing on a mismatch, and readers check each row and entry as they use it (M1): no reader downloads a map; (2) every replaying reader downloads and checks every committed map: 293 MB a device a cut-over at 1M paths; (3) evs hashes the parts inside the PATH_EPOCH commit: 40 GETs of 7 MiB in a commit's 5 s, or the hash redefined over part hashes, a format change. Recommendation: (1). **Answered: QD-610, option 1**, the copy job checks the whole map; EVS1-M2-44 landed it.

**Questions this section builds on.** `evs1-m2-24-root-directory-names`: option 1, restated above with what a path epoch adds. `evs1-m2-16-due-classification`: option 1 as built, the client calling the same function, so a change of option changes both at once. `evs1-m2-27-every-ref-lease-epoch`: option 1; with option 3 a whole-repo subscription only loses latency on refs in other epochs. `evs1-m2-10-directory-marker-version`: option 2 as built; nothing here reads a directory marker's version but as an upper bound, and `names_leaf_*` take fields 7 and 8 so option 1's field 6 stays free. `evs1-m2-39-head-index-epoch`: option 1, **answered so (QD-640)**: format-1 code reads past a head's `index_epoch` (9.2.2); a PATH_EPOCH names no index epoch, a format-1 mapper moves `.ur-index/` entries like any others since a move writes no file, and a format-2 kind-5 segment is uploaded again by a retoken (9.2.5), which is EVS2's to carry. None of the five blocks a held task but the first, which EVS1-M2-46 built on its recommendation (QD-612). The other three stand on the option named here.

## 10. DROP lists a phone can check (§11.6, §11.7, §11.9)

Status: pending

Tasks held until complete: EVS2-M10-09, EVS2-M10-10, EVS2-M10-22, EVSB-M10-03, EVSB-M10-04.

## 11. Canonical text extraction and exact body sizes for search

Status: complete (2026-11-10)

Tasks held until complete: SEARCH-M10-31, SEARCH-M10-36.

Vectors: `sidecar/testdata/index/conformance/` (`mail.json`, `file.json`, `entities.json`, `charsets.json`, `sizes.json`). New tasks: `.stack/plan/proposals/details-11-tasks.md` (SEARCH-M10-42, SEARCH-M10-43, SEARCH-M10-44). Questions filed: `.stack/questions/details-11-own-decoders.md`, `details-11-extraction-bounds.md`, `details-11-body-encoding.md`, `details-11-small-readings.md`. Questions this section answers, each as 11.9 says: `search-m10-05-extractor-unstated-bytes`, `search-m10-07-extractor-field-placement`, and `plan-SEARCH-exact-body-sizes` as the owner decided it (QD-215). It amends one proposed fill, QD-474, in three places that 11.9 names.

### 11.1 The problem

Two things in §11.14 must come out byte for byte the same on every device, and neither is written down far enough to build.

**Extraction.** An index entry is a document's row and its key set, and a key set is the trigrams of the document's normalized text. A device that holds a document's text rebuilds the entry and compares it with what the writer committed, and raises `index_mismatch` naming the signer when they differ (§11.14's coverage and reproduce rows; FI-22). So every byte the extractor hands the normalizer is a format byte. §11.14's extract row gives mail three lines, and `protocol/INDEX-FORMAT.md`'s Extractor 1 a dozen. Two implementations were written apart from them, as D-TEST-14 asks: `indexExtractMail` (SEARCH-M10-06) and SearchOracle's extractor (SEARCH-M10-07). Three things are wrong.

*A. The two disagree.* On honest mail they agree. On the inputs below, each a vector in `mail.json`, they do not, and each difference changes the key set:

```text
vector                         input                                      index            oracle
x-script-end-name              a<script>x</scriptx>y</script>z            az               ayz
t-base64-nbsp-stops            base64 body  SGVs U+00A0 bG8=              Hel              Hello
w-charset-with-space           Subject: =?UTF 8?Q?a?=                     as written       a
w-nbsp-between, w-cr-between   =?UTF-8?Q?a?= U+00A0 =?UTF-8?Q?b?=         a U+00A0 b       ab
p-sections-without-zero        filename=plain.txt; filename*1=b           plain.txt        (empty)
p-sections-empty-fall-through  filename*0=""; filename=plain.txt          plain.txt        (empty)
p-sections-repeat              filename*0=a; filename*0=b                 a                b
b-unterminated                 a multipart with no close delimiter,       two CR LF        two
                               whose last part is  two CR LF
```

The first, second, third and fifth are the ones question search-m10-05-extractor-unstated-bytes lists. The other four were found here, by running both over the vectors. To look for more, a copy of the oracle was made to read as the index does at exactly these six places (the script end tag, the bytes base64 skips, a word's charset, what counts as space between two words, RFC 2231's sections and precedence, the last part's line break) and fuzzed against the index: 1,533,211 executions from the vectors as seeds found no other difference.

*B. Where they agree, they agree because both call the same library, and what those calls do on malformed input is written nowhere.* Each of these is what Go 1.27.3 does today, shown by a vector, and none is a rule of the format:

```text
t-qp-long-line        mime/quotedprintable reads lines through a 4,096 B buffer: a quoted-printable part with one
                      longer line loses everything after that line's first 4,096 B. Both extractors lose it.
t-qp-control-bytes    the same reader stops at a NUL, an ESC or a DEL: the rest of the part is lost
t-base64-unpadded     encoding/base64 gives nothing for a last group without its padding: a body that is cut, or
                      whose writer left the padding off, loses its last one or two bytes
e-one-digit           html.UnescapeString leaves "&#9 x" as it is, and decodes "&#9;x" and "&#65 x"
e-no-digits           it reads "&#x;" as U+FFFD
e-overflow            it adds digits in 32 bits: "&#4294967361;" is "A"
e-two-code-points     it has 2,229 of HTML's 2,231 names: "&nLt;" and "&nGt;" stay as written
h-value-nbsp-stays    strings.TrimSpace trims U+00A0, U+0085 and 23 more code points from a header value
h-name-ascii-case-only  strings.ToLower reads "Content-D" U+0130 "sposition" as Content-Disposition
c-label-not-ascii     htmlindex.Get lowercases a label by Unicode: U+212A "oi8-r" names koi8-r
c-replacement-empty   a part labelled iso-2022-kr or hz-gb-2312 decodes to one U+FFFD, even when it is empty
p-section-signed      strconv.Atoi reads "filename*+0" as section 0, and a section number past 2^31 parses on
                      64-bit legs and fails on 32-bit ones
w-b-carriage-return   base64 inside an encoded word skips a CR
```

§11.14's determinism row forbids "library-version input", and QD-474 keeps the HTML parser out for that reason. The same holds for these calls: a Go release that fixes the 4,096 B limit, or the 32-bit sum, changes which bytes a writer indexes, and then every reader built on the other release reports an honest writer. The Unicode version is pinned and checked at start; the standard library's parsers are not, and cannot be, since they carry no version of their own.

*C. Nothing bounds memory.* Both extractors hold the message, each part decoded, each part again in UTF-8 and the joined text at once: the landed one allocates 2.5 times a 50 MiB message that is one base64 text part, and 8 to 10 times a small HTML message (11.4). §11.15 gives the iOS app 4 MiB of working set and "never a whole file ... over 1 MiB in RAM", and the owner directed on 2026-11-10 that bulk state lives in storage (QD-641). A one-pass reading in fixed memory is not possible under the rules as the two read them, because three of them need unbounded lookahead: a header value of any length is joined before its encoded words decode; a delimiter line may carry any run of trailing whitespace; so may a quoted-printable soft line break.

*D. Field order and placement are unstated* (question search-m10-07-extractor-field-placement): where a file's path goes, where attachment names go among the text parts, how To and Cc and several parts join, and what each chunk past the first carries. The two implementations took the same readings, pending an answer.

**Sizes.** D-EVS-59 makes every `SearchRequest` body exactly 4,016 B and every `SearchReply` body exactly steps × 16,384 B, so that a relay learns nothing from a length. The only filler is `pad`, proto field 15: one tag byte, a varint length, then zeros, and proto3 leaves an empty field out. So `pad` adds 0 bytes, or 3 to 129 (a one-byte length), or 131 to 16,386 (two), or 16,388 and more (three). It cannot add 1, 2, 130 or 16,387. Run against the marshaler for every pad length to 70,000, those four are the only gaps up to 65,536. Concretely:

```text
a request whose other fields encode to 4,015 B, 4,014 B or 3,886 B       cannot be made 4,016 B
a one-step reply whose other fields encode to 16,383, 16,382 or 16,254 B cannot be made 16,384 B
a two-step reply whose other fields encode to 16,381 B                   cannot be made 32,768 B
   (three steps: 32,765 B; four: 49,149 B)
```

A reply reaches these whenever its hits nearly fill a step: the size tests of 11.3 build replies of 6, 11 and 17 hits that sit exactly on the last gap at two, three and four steps. The owner decided the approach on 2026-11-06 (QD-215): no wire change, every other field stops 131 B short of the body's size, a multi-step reply "holds one hit back", and `SearchFilters` is capped at 768 B. What that leaves open is everything an implementer needs:

- the pad's length as a function, and which contents are refused;
- which hits a reply keeps, when the fields that describe the page (`complete`, `checked_through_ms`, `counts`) change size with the hits kept;
- a proof that a request always fits and that a reply with a hit to give always returns one, which needs a cap on every field, and two fields have none (`SearchHit.correction`, `SearchCoverage.chain`);
- what a receiver checks. "A non-zero pad" is INVALID (§11.14's status row), but a body can carry `pad` twice, the parser keeping the last, or carry a field this version does not know, and either hides non-zero bytes from that check;
- the landed `padSearchReply` (`rpc_search.go`), which tries five pad lengths and fails on a gap, after which its caller answers a small `UNAVAILABLE` Error: a failure after parsing that is not padded, which D-EVS-59 forbids.

### 11.2 The design

Extraction is one function, written out below in full. It calls no parser of the standard library or of any module: base64, quoted-printable, character references, header fields, parameters and multipart bodies are each a rule here. What it takes from outside is tables, each pinned: Unicode 17.0.0 and the charset decoders, both from golang.org/x/text v0.43.0 and Go's `unicode` package, which normalizer 1 already pins and checks at start; HTML's named character references, a list its standard has frozen, held in `entities.json`; and the block tags, listed here. Five limits make it computable in one pass with fixed memory (11.2.8). It is total: every byte string has exactly one output and there is no error to return.

The identifiers stay extractor 1 and normalizer 1. Index format 1 freezes at M10's exit (§23.8) and no index exists outside tests, so this section defines extractor 1 rather than adding a second. `protocol/INDEX-FORMAT.md`'s Extractor 1 and Documents sections are replaced by 11.8's text.

Bodies keep the owner's rule, made exact: one function gives the pad's length, one predicate says which contents can be sized, the builders keep contents inside it by caps that 11.3 proves sufficient, and a receiver accepts a body only if it is the one encoding of its message. `search.proto` does not change.

#### 11.2.1 Terms, constants and tables

```text
LF 0x0A   CR 0x0D   SP 0x20   HT 0x09
white      the bytes 0x09 to 0x0D and 0x20
blank      SP and HT
lower(x)   x with each byte 0x41-0x5A raised by 0x20, every other byte as it is; "ignoring case" means equal
           under lower
trim(x)    x without its leading and its trailing white bytes
letter     A-Z and a-z; digit 0-9; alphanumeric either; hex digit 0-9, A-F and a-f
```

No rule below reads a header, a parameter, a label, a tag name or an encoding's name as Unicode text: names compare under `lower`, and only white bytes are trimmed. Constants are facts of the format, never settings:

```text
HeaderMax       16,384 B   a logical header line, and the joined values of one field name (H4, H6)
LineWindow       1,024 B   the longest delimiter line (B1); the longest blank run inside a soft line break (T3)
MimeDepth           16     the multipart levels entered (M2)
ChunkBytes   1,048,576 B   a document's share of its source's text (D4)
Overlap            256 B   what a document repeats of the next (D4)
SniffWindow      8,000 B   the bytes that decide text or binary (S2)
TitleMax            80 B   a file's title (S4)
FieldCut         1,024 B   normalized subject, from, to and title (N6)
KeySetMax      524,288 B   a key set's encoding, past which its document is skipped (D6)
```

Tables, each part of extractor 1 or normalizer 1:

```text
Unicode       17.0.0: general categories and scripts from Go's unicode package (unicode.Version), normalization
              and case folding from golang.org/x/text v0.43.0 (norm.Version, cases.UnicodeVersion). A build
              linking anything else is another normalizer and writes nothing (INDEX-FORMAT.md's Tables).
charsets      golang.org/x/text v0.43.0's encoding/htmlindex: 228 labels naming 40 encodings, listed in
              charsets.json, and that module's decoder for each (C1-C3)
references    HTML's 2,231 named character references, 106 of them also without their ';' and 93 of them two
              code points: entities.json, SHA-256 9e7bac4a454044f307050b23fefa224beea56525742cc4774e1d4c6da6d40e57
block tags    address article aside blockquote br center dd details dialog dir div dl dt fieldset figcaption
              figure footer form h1 h2 h3 h4 h5 h6 header hgroup hr li main menu nav ol p pre section summary
              table tbody td tfoot th thead tr ul                                              (44 names; X4)
C1 table      what numeric references 128 to 159 mean, in order (E1): U+20AC 0081 201A 0192 201E 2026 2020 2021
              02C6 2030 0160 2039 0152 008D 017D 008F 0090 2018 2019 201C 201D 2022 2013 2014 02DC 2122 0161
              203A 0153 009D 017E 0178
```

#### 11.2.2 Normalizer 1, whole

Normalizer 1 is `protocol/INDEX-FORMAT.md`'s, unchanged. It is restated here with every byte §11.14's text row leaves open, so that this section holds the whole path from a file's bytes to a key set.

```text
N1  Each byte that does not begin a well-formed UTF-8 sequence becomes U+FFFD, one for each such byte: an
    overlong form, a surrogate, a value past U+10FFFF and a sequence cut short by the end of the value each
    give one U+FFFD a byte. A well-formed U+FFFD stays.
N2  NFKC, as x/text's norm.NFKC gives it, its stream-safe rule included: after 30 non-starters it inserts
    U+034F.
N3  Full case folding, as x/text's cases.Fold() gives it with no locale, then U+AB70-U+ABBF to
    U+13A0-U+13EF and U+13F8-U+13FD to U+13F0-U+13F5 (QD-256).
N4  NFD. Then each code point of category Mn is dropped when the nearest code point before it in the value
    that is not Mn is of category L and of script Latin, Greek, Cyrillic, Arabic or Hebrew (the Script
    property, not Script_Extensions). With no such code point before it, at a value's start, it stays. Then
    NFC.
N5  Each maximal run of code points outside categories L, M and N becomes one SP. U+FFFD is in such a run.
N6  For fields 1 to 4, the result is cut to its longest prefix of at most FieldCut bytes that ends on a code
    point.
N7  A document's text is, for each field in number order whose value is not empty: SP, the field's normalized
    value, SP. Nothing is trimmed, so a value that normalizes to a leading or trailing space shows two.
N8  A document's key set is the distinct values b0 x 65,536 + b1 x 256 + b2 over every three consecutive
    bytes of its text, the windows across two fields' padding included. A text under 3 B has none.
```

What the row left open, and how each is settled: N1 counts bytes, not maximal subparts. N1 to N5 run on each field's value by itself, with N4's "nearest code point before" starting afresh, and on each chunk by itself, so a chunk that begins or ends inside a character shows U+FFFD there. N6 cuts after N5, on normalized bytes, and may cut between a base and a mark N4 kept. A value that is not empty never normalizes to nothing, so N7's test is on the value before normalization.

#### 11.2.3 Documents: kinds, fields, chunks and rows

```text
D1  A version is extracted as mail when its repo is a mailbox, or a general repo laid out as a group inbox
    (§15.7), and its path begins "m/". Every other version that §11.14's never row lets in is extracted as a
    file. A record entry's or a derived document's fields are its class's (§16.8, §16.11).
D2  A file that S1-S3 find to be text has, for each chunk c of its text (D4), one document: field 4 is the
    file's title (S4), one SP and the path's bytes; field 5 is c. Field 4 has that form even when the title
    is empty. Fields 1-3 are empty.
D3  A message has, for each chunk c of its body text, one document: field 1 is the decoded Subject, field 2
    the decoded From, field 3 the decoded To and the decoded Cc, each left out when empty and joined by one
    SP when both stand, and field 5 is c. Field 4 is empty. "Decoded X" is W applied to H6's joined value of
    X, of the message's own header block alone. The body text is the walk's pieces (M1-M6) in the order the
    walk gives them, the empty ones left out, joined by one SP.
D4  The chunks of a text t are t[k x ChunkBytes : min(len(t), (k+1) x ChunkBytes + Overlap)] for k = 0, 1, ...
    while k x ChunkBytes < len(t), and the one empty chunk when t is empty. Chunk k is the document with
    chunk number k. Bytes are counted in the text as extracted (a file's after S1 and S3, a message's body
    text), before normalization. Every chunk carries the same fields 1-4.
D5  A document's row is INDEX-FORMAT.md's: its locator the path's bytes, its subject, from and to the values
    of fields 1-3 before normalization, its title the title of S4 alone, never the path, each with N1 applied
    and then cut by that file's Trimming; its size the length in bytes of the whole file or message, the
    same on every chunk's row.
D6  A document whose key set would encode past KeySetMax is skipped: it has no entry, and where its key was
    indexed before, its version is a tombstone (§11.14's sniff row).
```

D2, D3 and D4 are question search-m10-07-extractor-field-placement's option 1. A path's words are found through field 4. A message's attachment names sit in field 5 where their parts stand, so a phrase can span a name and the text beside it only as they are laid out in the message. Field 4's cut (N6) means a path's tail past 1,024 normalized bytes of title and path is not indexed.

A document's `doc_key`, version and attributes are not extraction's: `doc_key` is INDEX-FORMAT.md's Documents, from the path's bytes and the chunk number, and so does not move with a path epoch (section 9), whose tokens name index files and never enter a document.

#### 11.2.4 Files

```text
S1  A file that begins FE FF is UTF-16 big-endian, and one that begins FF FE little-endian. The mark is
    dropped. Each two bytes after it are a code unit; a surrogate pair is its code point; a surrogate with no
    partner is U+FFFD; an odd last byte is U+FFFD. The text is the result in UTF-8, and the file is text.
    Nothing else is asked of it: U+0000 is allowed.
S2  Otherwise take the window, the file's first SniffWindow bytes or the whole file when it is shorter. The
    file is binary, and gives no document, when the window holds a byte 0x00, or when, reading well-formed
    UTF-8 sequences from the window's start, a byte is met that does not begin one, unless the bytes from
    there to the window's end are a proper prefix of a well-formed sequence (a character the window cut).
    The prefix test is exact: E0 80, ED A0 and F4 90 begin nothing. Otherwise the file is text, and its text
    is all of its bytes, whatever lies past the window.
S3  A text of S2 that begins EF BB BF loses those three bytes, once.
S4  The title: split the text at each LF. The title line is the first line that holds a code point of
    category L or N, reading the line as UTF-8 with N1's rule (so U+FFFD, which is neither, stands for each
    ill-formed byte). Take that line; drop its leading run of '#' and SP bytes; drop its trailing run of SP,
    HT and CR bytes; apply N1; cut to the longest prefix of at most TitleMax bytes that ends on a code point.
    No such line: the title is empty.
```

S3 is new: without it a file saved with a UTF-8 mark shows the mark and its heading's "# " in its title.

#### 11.2.5 Mail

A message is read as RFC 5322 and MIME lay it out, by the rules below and no others. `extract_mail(content)`:

```text
fields, body = header_block(content)                                      H1-H5
subject = words(joined(fields, "subject"))                                H6, W
from    = words(joined(fields, "from"))
to      = join_nonempty(words(joined(fields, "to")), words(joined(fields, "cc")))
pieces  = []
walk(fields, body, 0, pieces)                                             M1-M6
text    = join_nonempty(pieces...)             the non-empty ones, in order, with one SP between
one document per chunk of text (D3, D4)
```

**The header block.**

```text
H1  Lines end at LF. A line's content is its bytes before the LF, less one CR when it ends in one. The last
    line may end at the end of the input instead.
H2  The header block is the lines from the start up to the first line whose content is empty. That line
    belongs to neither part; the body is everything after its LF. With no empty line, everything is header
    and the body is empty. A line of only blank bytes is not empty.
H3  A line whose first byte is blank, when a logical line stands before it, is appended to that logical
    line as it is, its leading blank bytes included. Any other line begins a logical line.
H4  A logical line is at most HeaderMax bytes: bytes past that are dropped as they arrive.
H5  A logical line with no ':' is no field. Otherwise its name is lower(trim(bytes before the first ':'))
    and its value is trim(bytes after it). Fields keep their order.
H6  first(name) is the value of the first field of that name, or empty. joined(name) is the values of every
    field of that name, in order, with one SP between each two, an empty value included, cut to its first
    HeaderMax bytes.
```

**Encoded words** (RFC 2047). `words(v)` scans v from the left:

```text
W1  An encoded word is "=?" C "?" E "?" T "?=", where C, E and T hold no '?', and E is one byte: B, b, Q
    or q. It may stand anywhere in v, inside a token too.
W2  Its charset is C up to its first '*'. It is not an encoded word when the charset is empty, when the
    charset or T holds a blank byte, or when W3 or W4 refuses T. Its text is T decoded by W3 or W4 and then
    by C3 under the charset's label.
W3  B: drop every '=' at T's end. What is left must be base64 alphabet bytes (A-Z a-z 0-9 + /) and not 1
    more than a multiple of 4 long, or T is refused. Each 4 bytes give 3; a last 2 give 1 and a last 3 give
    2, the unused bits ignored. An empty T decodes to nothing.
W4  Q: '_' is SP; '=' and two hex digits are that byte; '=' followed by anything else, or by fewer than two
    bytes, refuses T; every other byte is itself.
W5  Find the leftmost "=?" at or after the scan position. If an encoded word starts there, take it and move
    the position past its "?="; if not, move the position 2 bytes on and look again. When none is left, the
    rest of v is text.
W6  The text between two encoded words is dropped when it is empty or only blank bytes, and kept otherwise.
    Text before the first word and after the last is kept. So is text between a word and something that is
    not one.
```

**Media values and parameters** (RFC 2045, 2183, 2231), for Content-Type and Content-Disposition:

```text
P1  The value is lower(trim(bytes before the first ';')). An absent or empty field has the empty value and
    no parameters.
P2  The bytes after the first ';' are split at each ';' that is outside quotes. A '"' opens quotes and the
    next '"' closes them; inside quotes a '\' and the byte after it are passed over together. A quote left
    open runs to the end.
P3  A piece with no '=' is no parameter. Otherwise its name is lower(trim(bytes before the first '=')) and
    its raw value trim(bytes after it). A name ending in '*' is extended, and loses that '*'. If the name
    then holds a '*', the bytes before the first one are the parameter's name and the bytes after it its
    section, which must be 1 to 9 digits and nothing else, or the piece is no parameter. So a parameter has
    up to three kinds of piece: plain, extended, and sections 0, 1, ..., each plain or extended. Of two
    pieces of one name and kind (and one section number), the first counts.
P4  A plain piece's value is its raw value unquoted: when it is at least 2 bytes and begins and ends with
    '"', those two go, and inside, a '\' followed by a byte gives that byte. Anything else is as written. An
    extended piece's raw value is never unquoted.
P5  param(name), in this order: (a) if it has a section 0, join sections 0, 1, 2, ... up to the first
    number that is missing; if the result is not empty, that is the value; (b) else its extended piece;
    (c) else its plain piece; (d) else empty.
P6  An extended value is charset ' language ' text when it holds two "'" (the first two split it), and
    otherwise all text with no charset. Its text is percent-decoded: '%' and two hex digits are that byte;
    if any '%' is followed by anything else, the whole text stands as written. In (a), an extended section
    is percent-decoded, a plain one is not, and only section 0, when extended, is split for a charset. The
    bytes are then decoded by C3 under that charset's label.
```

**Charsets.**

```text
C1  A label is trimmed. It names an encoding when every byte of it is 0x21 to 0x7E and lower(label) is one
    of charsets.json's 228 labels.
C2  No label, a label that names nothing, and a label that names utf-8 or replacement leave the bytes as
    they are. Ill-formed UTF-8 then meets N1.
C3  Any other label's bytes are decoded by x/text v0.43.0's decoder for its encoding. Those decoders answer
    malformed input with U+FFFD and never fail. No charset is guessed from content.
```

**The walk.** `walk(fields, body, depth, pieces)`:

```text
M1  type = P(first("content-type")), disposition = P(first("content-disposition")). The media type is
    type's value, or text/plain when that is empty; type's parameters stand either way.
M2  A media type beginning "multipart/": let b = type.param("boundary"). If b is empty, or depth >=
    MimeDepth, the entity gives nothing. Otherwise for each part of parts(body, b) (B1-B4), in order:
    walk(header_block(part), depth + 1). The entity's own name is not read. Every part is walked, the parts
    of multipart/alternative like any others.
M3  Any other entity: its name is disposition.param("filename"), or when that is empty type.param("name").
    A name that is not empty gives the piece words(name).
M4  If disposition's value is "attachment", the entity gives nothing more.
M5  text/plain gives the piece C3(type.param("charset"), transfer(first("content-transfer-encoding"), body)).
    text/html gives the piece html_to_text of the same (11.2.6).
M6  Every other media type gives nothing more: no bytes of it are decoded, and a message/rfc822 part is not
    entered.
```

**Multipart bodies.** `parts(body, b)`:

```text
B1  Split body into lines at each LF (a line's bytes exclude the LF; the last line may end at the end). A
    line is a delimiter line when it is at most LineWindow bytes and, without its trailing run of SP, HT and
    CR bytes, equals "--" b; it is the close delimiter when it equals "--" b "--". The comparison is of
    bytes, from the line's first byte.
B2  A part begins after a delimiter line's LF and ends before the next delimiter or close delimiter line,
    less that line's own break: when the part's last byte is LF it goes, and then a CR before it goes.
B3  Lines before the first delimiter line belong to no part. At the close delimiter the parts end, and
    whatever follows it belongs to none.
B4  With no close delimiter, the last part runs to the end of body and keeps its last line break.
```

When a line is a delimiter of two nested multiparts, the outer one takes it, since the inner body is cut out of an outer part before it is split. A boundary that ends in SP, HT or CR, or is longer than 1,022 B, matches no line, and its multipart gives nothing.

**Transfer encodings.** `transfer(e, body)`:

```text
T1  lower(trim(e)) equal to "base64" selects T2 and "quoted-printable" T3. Anything else, absent included,
    leaves body as it is.
T2  base64: white bytes are skipped. Alphabet bytes are taken up to the first byte that is neither, '='
    included, where decoding ends. Each 4 give 3 bytes; at the end a last 2 give 1 and a last 3 give 2, the
    unused bits ignored; a last 1 gives none.
T3  quoted-printable, left to right: '=' and two hex digits are that byte. Any other '=' is a soft line
    break, which gives nothing, when after it come at most LineWindow blank bytes and then LF, or CR LF, or
    the end of body; all of that is consumed. Any other '=' is itself. Every other byte is itself, control
    bytes included. No line is too long, and trailing blank bytes of a line stay.
```

#### 11.2.6 HTML to text

`html_to_text(t)` is `references(tags(t))`: every tag goes first, and character references are decoded in what is left, once.

**Tags.** `tags(t)` reads t from the left. A byte other than '<' is copied. At a '<':

```text
X1  "<!--" opens a comment, which ends after the first "-->" that begins 4 or more bytes past the '<'. It
    gives nothing.
X2  Otherwise "<!" or "<?" opens a declaration, which ends after the next '>'. It gives nothing.
X3  Otherwise '<' followed by a letter or '/' opens a tag, which ends at the first '>' outside quotes,
    looking from the byte after the '<': a '"' or a "'" opens quotes and the next byte equal to it closes
    them. The tag is a closing tag when the byte after '<' is '/'.
X4  The tag's name is lower of the alphanumeric bytes that follow the '<', or the "</", up to the first
    byte that is not one, and may be empty. A tag whose name is a block tag gives one SP, closing or not.
    Any other tag gives nothing.
X5  A tag named script or style that is not a closing tag also takes its content: look, from the byte
    after the tag's '>', for the first "</" followed by that name ignoring case and then by the end of t or
    a byte that is not alphanumeric. That "</" opens a tag by X3, and reading resumes after its '>'. All of
    it gives nothing, the SP of X4 too, since neither name is a block tag.
X6  Any other '<' is copied.
X7  A comment, declaration or tag with no end, a script or style with no end tag, and an end tag with no
    '>' each take everything to the end of t.
```

**Character references.** `references(u)` reads u from the left. A byte other than '&' is copied. At an '&':

```text
E1  "&#", then an optional 'x' or 'X', then one or more digits (hex digits after an x), then an optional
    ';' is a numeric reference; all of it is consumed. Its value is the digits' number, held at 0x110000
    once it passes that. A value 0x80 to 0x9F gives the C1 table's code point; 0, 0xD800 to 0xDFFF and
    anything past 0x10FFFF give U+FFFD; any other value gives that code point. With no digit, the '&' is
    copied and reading goes on after it.
E2  Otherwise take the alphanumeric bytes after the '&', as many as there are. With none, the '&' is copied
    and reading goes on after it. Else the name is those bytes and a ';' if one follows them. If the name is
    one of the 2,231, its one or two code points are given and all of it is consumed. Names match by exact
    bytes: "AMP;" is one and "Amp;" is not.
E3  Otherwise, for k = min(6, the name's length - 1) down to 2: if the name's first k bytes are one of the
    106 names without ';', its code point is given and the '&' and those k bytes are consumed. The first k
    that matches counts.
E4  Otherwise the '&' and the name are copied.
```

E1 to E4 are HTML's own rule for text outside attributes, with its table whole. They are not `html.UnescapeString`: 11.1 B lists the four places that function departs from them.

#### 11.2.7 Malformed input

Nothing is refused and nothing is guessed. Each kind of damage has one reading, already given by a rule; this table collects them.

```text
no empty line after the header                 all header, empty body (H2)
a header line with no ':'                      passed over; a continuation still joins it (H3, H5)
a field or a joined value past 16,384 B        its first 16,384 B (H4, H6)
several Subject, From, To or Cc fields         all, joined by SP before their words decode (H6)
several Content-Type fields                    the first (H6)
an encoded word that breaks W1-W4              text, as written
an unknown charset, or none                    the bytes as they are; N1 maps what is not UTF-8 (C2)
a multipart with no boundary, or 17 deep       nothing from it (M2)
a part with no header, or no blank line        text/plain, or all header and an empty body (M1, H2)
no close delimiter                             the last part runs to the end (B4)
a delimiter line past 1,024 B                  not a delimiter: it is part of the body (B1)
base64 with a byte outside its alphabet        what came before it, the last partial group decoded (T2)
an '=' that is neither an escape nor a break   itself (T3)
an unknown transfer encoding                   the body as it is (T1)
a tag, comment or script with no end           everything after it is dropped (X7)
a reference that names nothing                 text, as written (E4)
a file with a NUL or ill-formed UTF-8 in       binary: no document; where it was indexed, a tombstone (S2;
  its first 8,000 B                              §11.14's sniff row)
ill-formed UTF-8 past 8,000 B                  U+FFFD a byte, at normalization (N1)
a chunk whose key set passes 512 KiB           skipped (D6)
```

#### 11.2.8 One pass, fixed memory

The rules above are written over whole values. Each was chosen so that the same function can be computed in one pass over the message with a fixed amount of memory, and SEARCH-M10-44 builds that form for app hosts. A stage reads the bytes the stage before it gives:

```text
stage                    what it keeps                                         from
lines and delimiters     the current line's first 1,024 B; one held line       B1, B2
                         break; up to 16 boundaries of at most 1,022 B
header blocks            per entity, the first Content-Type, -Disposition      H4, H6
                         and -Transfer-Encoding lines, 16,384 B each; for
                         the message, the four joined values, 16,384 B each
base64                   up to 3 alphabet bytes                                T2
quoted-printable         an '=' and up to 1,024 blank bytes and a CR           T3
charset                  the decoder's state, a few bytes                      C3
tags                     a state, a quote byte, 8 B of a name, up to 8 B of    X1-X7
                         a match in progress
references               an '&' and up to 33 B                                 E1-E3
pieces                   whether anything was given yet                        D3
chunks                   the 256 B that two documents share                    D4
normalizer and key set   INDEX-FORMAT.md's: a few KiB, and the key bitmap      N1-N8
```

Four points are not obvious. (1) A line is tested as a delimiter against every open boundary, outermost first, once its LF arrives or 1,024 B have passed without one; a line break is held back until the next line is known not to be a delimiter, and dropped when it is one (B2). (2) A header line of interest is kept to 16,384 B and the rest of it discarded as it arrives; every other header line is discarded whole. (3) A document's key set is collected while its text passes; at a chunk's end the next 256 B are fed to it, the document is finished, and the same 256 B begin the next, so one key bitmap is live at a time. (4) A file's title is needed by its first document, and may lie anywhere in the file: the file is in storage, so the title is found by a first read that stops at the first line with a letter or a number, which for nearly every file is its first line, and the documents are built by a second.

A reference's 33 B is enough: the longest name is 32 B with its ';', a longer run can match no name whole, and E3 looks at 6 bytes. A tag's 8 B of name is enough: the longest name that matters is 10 B (blockquote, figcaption), and a longer run is compared as it arrives against the 44 names without being kept.

#### 11.2.9 Exact body sizes

A body is the deterministic proto3 encoding of its message, in which `pad`, the highest-numbered field of both messages, comes last. Write *content* for the length in bytes of that encoding with `pad` empty, and *size* for what the body must be: 4,016 for a request, steps × 16,384 for a reply, steps being the request's (1 to 4).

```text
Z1  A pad of L > 0 zero bytes encodes as 0x7A, L as a varint, and the L bytes: L + 2 bytes for L up to
    127, L + 3 up to 16,383, L + 4 up to 2,097,151.
Z2  pad_length(size, content): let gap = size - content. If 131 <= gap <= 16,386, L = gap - 3. If 16,388
    <= gap <= 2,097,155, L = gap - 4. Otherwise there is none.
Z3  A content is admissible for a size when 0 <= content <= size - 131 and size - content is not 16,387.
    Builders build only admissible contents, and for those Z2 always answers.
Z4  Caps, which builders keep and receivers check:
      SearchRequest   query at most 512 B; at most 64 repos; a repo_id 16 B and a ref_id 16 B or empty;
                      filters at most 768 B as encoded (QD-215); steps 1 to 4; and, with page above 0, no
                      query, scope, repos, since_ms, until_ms, filters or fuzzy
      SearchReply     at most 64 coverage rows, each with 16 B ids and a chain of at most 32 B; at most 20
                      hits
      SearchHit       ids and signer 16 B; locator at most 512 B; correction at most 256 B; at most 8
                      fields, each text at most 256 B; snippet at most 200 B
Z5  A request is built by filling its fields within Z4, taking its content, and setting pad to
    pad_length(4,016, content) zero bytes. Within Z4 a request's content is at most 3,778 B on page 0 and
    36 B on a later page, so it is always admissible. A search that would break a cap is not sent:
    one whose filters pass 768 B stays on the device (QD-215), and more than 64 repos go in further
    requests (§11.14's order row).
Z6  A reply is built from the hits still to give, in rank order, and a function head(k) that gives the
    reply's other fields when the first k of them are returned (status, phase, complete, checked_through_ms,
    counts, and on page 0 the coverage rows). For k from min(20, the number to give) down to 0: take the
    content of head(k) with those k hits; the first k whose content is admissible is the reply, padded by
    Z2. Hits past k stay with the cursor for the next page. k = 0 is always admissible, and so is k = 1 when
    there is a hit (11.3), so a page with a hit to give returns at least one.
Z7  A failure after parsing is a reply of its status alone, with the version fields and, where the request
    parsed, its search_id and page. Its content is at most 90 B, so it is admissible at every size.
Z8  A receiver accepts a body only when all of these hold, checked in this order:
      (a) its length is the size: 4,016 B for a request; for a reply, the steps the requester asked times
          16,384;
      (b) it parses as its message;
      (c) its search_version is one this build supports;
      (d) it holds no field this build does not know, at any depth, and marshaling the parsed message
          deterministically gives the same bytes;
      (e) every byte of pad is zero;
      (f) its fields are within Z4.
    An indexer answers a request that fails (a), (b), (d), (e) or (f) with status INVALID and one that
    fails (c) with UNSUPPORTED_VERSION, each by Z7 at the request's steps where (b) held and steps is 1 to
    4, and at one step otherwise. A requester treats a reply that fails (a) to (e), or that names another
    search_id or page than it asked, as no reply: the indexer failed, and §11.14's failover row applies. For
    (f) on a reply it drops what is past a cap and keeps the rest: hits past 20, a hit with a wrong-length
    id or a locator past 512 B, a hit's fields past 8, and a field, snippet or correction past its length.
```

Z8 (d) is what makes (e) mean anything. Deterministic marshaling writes fields in number order, each scalar once and at its shortest, so a body that passes (d) has exactly one `pad`, at its end, and nothing else in it that the parser did not read. (c) comes before (d) so that a request of a later version, which may carry fields this build does not know, is told UNSUPPORTED_VERSION and not INVALID. Unknown status and served codes are SEARCH-M10-31's as planned: never read as OK or served.

**Wire changes.** None to `search.proto`'s fields or numbers. Three comments change (11.8): `SearchHit.correction` gains "<= 256 B", `SearchCoverage.chain` "<= 32 B", and `SearchFilters` "<= 768 B encoded". §11.14's status row gains Z8 (d)'s refusal.

**What others build on.** Problem 1 (merges, roll-ups and the journal) may rely on: an entry is a function of its own document; a document is a function of its path's bytes, its version's bytes and the tables of 11.2.1; a version's documents are numbered 0 to n - 1 with n = max(1, ⌈len(text) / ChunkBytes⌉), so a version with fewer chunks than the one before leaves tombstones for exactly the chunk numbers from its n up; two builds that extract one version write equal rows and key sets, so a merge never needs the text, and a host with the text checks an entry by building it. Problem 7 (remote search) may rely on Z2, Z3 and Z6 as functions, on Z7 for every failure after parsing, and on Z8's order; it owns what `head(k)` computes.

### 11.3 Invariants and why they hold

No part of this is concurrent: extraction and sizing are pure functions, so there is no model. The proofs are arguments over the rules, and the evidence is vectors, fuzzing against the landed code and exhaustive runs of the size arithmetic against the marshaler.

```text
R1 Total       extract_file and extract_mail return for every byte string and every path, with no error; a
               message gives at least one document
R2 A function  their result depends on the path's bytes, the content's bytes and 11.2.1's tables alone: no
               clock, locale, map order, integer width, build leg or library parser enters it
R3 Bounded     time is linear in the input; the fields hold at most 3.6 times the input's bytes plus a
               constant
R4 One pass    the one-pass form of 11.2.8 computes the same function in fixed memory
R5 Kept out    no byte of an entity's body that M4 or M6 stops at reaches a field, and no header field but
               Subject, From, To and Cc of the message's own block
R6 Idempotent  N1-N5 give the same value when applied twice; nothing else is claimed to be

Z-A Exact      a body built from an admissible content is exactly its size
Z-B Requests   every request within Z4's caps is admissible
Z-C Progress   a reply always has an admissible form, and one with at least one hit when there is a hit
Z-D One form   a message has one body, so a pad of zeros hides nothing
```

**R1.** Every rule ends in an "otherwise" that takes input as text or drops it, and no rule can fail: H5 passes over a line, W2 leaves a word as written, C2 leaves bytes, M2 and M6 give nothing, T2 stops, T3 and X6 copy a byte, E4 copies. Every scan moves forward: each step consumes at least one byte, or, in W5, moves the position 2 on. The searches that run ahead (X1's "-->", X3's '>', X5's end tag, a line's LF) either find their mark and resume after it or end that value. A message always reaches D4, which gives one chunk even for an empty text.

**R2.** Read the rules for what they take in. Bytes compare as bytes or under `lower`; the only sets of bytes are white, blank, letters, digits and the base64 alphabet. Numbers: a section is at most 999,999,999 and a numeric reference is held at 0x110000, so both fit 31 bits; everything else is a length. P3 keeps pieces by name and section, the first of each counting, and P5 reads them by name and by ascending section, so no order of a map is ever read. The tables are pinned and checked: the Unicode and x/text versions at start by `indexLinkedTables` (landed), the 2,231 references and 228 labels by the vector files, the block tags by vector `x-block-list`, the 40 decoders by the `c-sweep-` vectors over one sample. C3 is the one rule defined by reference to code, x/text v0.43.0's decoders, which normalizer 1 already makes part of the format; over 3,000 random inputs each, none of the 40 returned an error.

**R3.** Sizes by stage: base64 gives 3 bytes for 4 and quoted-printable never more than it takes; a charset decoder gives at most 3 bytes a byte (measured at exactly 3.00 over those random inputs, a single byte becoming U+FFFD or a three-byte character); removing tags only removes; a reference never grows except `&nLt;` and `&nGt;`, 5 bytes giving 6. So a part's text is at most 3.6 times its bytes, and a header value's at most 3 times its 16,384. Time: every stage is a scan with bounded lookahead (11.2.8's table), and the whole-value form reads a part once per multipart level around it, at most 17 times. W5's failed starts cost in all no more than the value's length, since each reads to the third '?' after it and every start holds one.

**R4.** By 11.2.8's table: every rule decides on the bytes it has plus a lookahead that the table bounds, and the three unbounded lookaheads of 11.1 C are gone (H4 and H6 cap a value, B1 caps a delimiter line, T3 caps a soft break's blank run). This is argued here and not run: SEARCH-M10-44 builds the form, and its fuzz target, equality with the whole-value form on every input and every split of it into writes, is the check.

**R5.** M4 and M6 return before any rule reads the body. H6 is called with seven names and no other: four for the message, three for each entity. Vectors `m-order`, `m-text-attachment`, `b-preamble-epilogue` and `h-transport-headers` carry a canary where it must not be read, and the landed `FuzzIndexExtractAttachment` keeps its claim.

**R6.** SEARCH-M10-03's fuzz target holds N1-N5 idempotent over every code point and 22 million strings, with QD-256's map. Extraction is not idempotent and nothing applies it twice. N7 is not either: a document's text has doubled spaces between fields that N5 would fold, and nothing normalizes a document's text again.

**Z-A.** Let gap = size - content. If 131 <= gap <= 16,386 then L = gap - 3 lies in 128 to 16,383, whose varint is two bytes, and 1 + 2 + L = gap. If 16,388 <= gap <= 2,097,155 then L = gap - 4 lies in 16,384 to 2,097,151, three bytes, and 1 + 3 + L = gap. `pad` is the last field and no other field's encoding depends on it, so the body is the content's bytes followed by those gap bytes.

**Z-B.** With every field at its cap and every integer at its widest, the marshaler gives a page-0 request 3,778 B: 2,432 for 64 repos, 515 for the query, 771 for the filters, 60 for the rest. A later page is at most 36 B. Both are under 3,885 = 4,016 - 131, and no request's gap can be 16,387.

**Z-C.** With 64 coverage rows and every integer at its widest, a reply without hits is at most 7,578 B, and one hit at its caps adds at most 3,248 B. So the content with no hit is at most 7,578 and with one hit at most 10,826, both under 16,253 = 16,384 - 131, the tightest size. Neither can be size - 16,387, which is at least 16,381. Z6's loop therefore ends at k >= 1 when there is a hit and at k = 0 otherwise. A failure's 90 B is admissible at every size: its gap is 16,294 or more at one step and past 16,388 at more.

**Z-D.** Z8 (d) accepts a body only if marshaling its parsed message gives it back, and the marshaler has one output for a message with no unknown field. So two accepted bodies that parse alike are equal, an accepted body has one `pad` and it is the body's tail, and (e) reads every byte of it.

**What was run**, on 2026-11-10 with go1.27.3 on darwin/arm64, x/text v0.43.0, against `sidecar` at c7b928f. The harness is a reference implementation written from 11.2's rules, the cases, and the size checks. It lives outside the repository, since this section changes no code; 11.6 says which task rebuilds each check as a test.

```text
vectors          360 cases through the reference: 320 messages, 40 files. 306 carry a field or a verdict written
                 by hand before the run, and all 306 matched. The landed normalizer and the oracle's give the
                 same text for every document of every case.
landed index     differs from the reference on 29 vectors, each named in 11.7; equal on the other 331, the six
                 of testdata/index/extract/ among them
landed oracle    differs on 38: those 29 where it reads as the index does, and the 9 of 11.1 A
completeness     the reference, switched to read as the landed index at each place 11.7 lists and nowhere
                 else, equals indexExtractMail over 2,840,431 fuzz executions seeded with the vectors, and
                 indexExtractFile over a 40 s run: the list of changes is whole, to that confidence
pad              every pad length 1 to 70,000 through the marshaler: the gaps it cannot fill, 0 to 65,536, are
                 1, 2, 130 and 16,387, and Z2 gives the marshaler's length for every other gap from 131
rule             for each of the five sizes and every content 0 to the size: admissible implies sizable; the
                 rule refuses 128 contents a size that a shorter pad would have sized (gaps 0 and 3 to 129)
requests         166,725 bodies: every query length 0 to 512 with every repo count 0 to 64, with no filters and
                 with filters of 3, 126, 127 and 768 B; each exactly 4,016 B, parsed back equal, and Z8 (d) true
replies          60,000 seeded random replies at 1 to 4 steps with 0 to 25 hits to give: each exactly its size,
                 Z8 (d) true, the kept hits a prefix, at least one kept whenever there was one; 1,058 held hits
                 back
the gap          replies built to sit on it: 6 hits of 16,381 B at two steps, 11 of 32,765 B at three, 17 of
                 49,149 B at four; each is built with one hit fewer, and with one more when one more is waiting
refusals         a body of the right size with a non-zero pad byte, an unknown field, pad twice, or a varint
                 one byte too long is refused by Z8; so is one of the wrong size
```

### 11.4 Cost

Measured on the same host, one run each. "Landed" is `indexExtractMail` as it stands, which holds everything at once. The last column is what it allocated, as a multiple of the message.

```text
message                                           size        extract   normalize, keys   documents   allocated
49 KiB, two alternatives, quoted-printable        49,401 B    0.5 ms    1.2 ms            1           9.5 x
50 MiB, one 49 MiB base64 attachment              52.7 MB     8 ms      0.5 ms            1           0.0 x
50 MiB, all one base64 text/plain part            53.1 MB     64 ms     1,117 ms          38          2.5 x
2 MiB of windows-1252 HTML, every byte growing    2.1 MB      9 ms      50 ms             2           8.1 x
```

- **Time.** Normalizing and collecting keys runs at 30 to 35 MB/s here and is 10 to 20 times extraction's cost on text; an attachment costs a scan for delimiter lines, about 6 GB/s. The rules of 11.2 add nothing that shows: the reference's plain loops for base64 and quoted-printable ran the worst case at 98 MB/s, three times faster than the normalizer that follows them. A phone at a fifth of this host's speed extracts and normalizes a typical message in under 10 ms and the 50 MiB all-text message, the largest §15's limits admit, in about 6 s, at §11.15's 5 MB/s floor.
- **Memory, whole-value form.** 2.5 to 10 times the message, as measured: the message, each part decoded, each part again in UTF-8, the joined text. For a 50 MiB message that is over 130 MB. It is fine on a desktop or the daemon (128 MiB budgets and up, §18) for the messages they meet, and it is why it must not be what an app host runs.
- **Memory, one-pass form.** 11.2.8's table summed: the line window 1 KiB, sixteen boundaries 16 KiB, one entity's three header lines 48 KiB, the message's four joined values 64 KiB, and under 1 KiB for every other stage: at most 132 KiB, whatever the message. Beside it stand the normalizer's buffers and one key bitmap, 2 MiB and up to 1 MiB of touched words (SEARCH-M10-03, landed), and the store's 64 KiB frame. That is inside §11.15's 4 MiB for the iOS app only because one bitmap is live at a time (11.2.8, point 3). The message itself stays in storage and is read once, front to back; a file is read twice when its title is not near its start (point 4).
- **Index size.** Extraction sets how many documents a version has: one per MiB of extracted text. Reading every alternative roughly doubles a typical message's text, and changes its key set little, since both alternatives hold the same words. The largest message, 50 MiB of single-byte text in base64, gives 37.5 MiB of bytes, up to 112 MiB of text and 108 documents, each skipped past 512 KiB of key set (D6): at most about the message's own size in index entries, as §11.14's document and sniff rows already allow.
- **Padding.** A request is one size computation and one marshal of 4 KiB. A reply is at most 21 size computations and one marshal of 16 to 64 KiB, well under a millisecond. Z8 (d) is one more marshal and a comparison per body received. The rule gives up at most 131 B of a body, 0.8% of a step, and the gap costs one hit of one page only when a content lands on one value in 16,384.

### 11.5 Failure modes

```text
malformed mail          read by 11.2.7's table. Nothing is refused, so no message is unsearchable for its
                        damage: the index holds what a lenient reader would show. Two devices read it alike (R2).
mail built to split     an input chosen so two honest builds disagree would turn the readers' check on an honest
  two devices           writer. Under R2 there is none; before SEARCH-M10-42 and -43 land there are the classes
                        of 11.1 A and B, so no index is written outside tests until both have landed.
a cut message           its last part runs to the end (B4); base64 decodes to its last whole or partial group
                        (T2); a last '=' is a soft break (T3); an open tag or script drops the tail (X7)
huge parts              time and memory as 11.4. An attachment of any size costs a scan. Text is chunked (D4),
                        and a chunk of noise is skipped (D6). The one-pass form never holds a part.
a huge header           a field past 16,384 B is cut (H4, H6): its tail is not indexed. A header block of any
                        length is read, each line of no interest discarded as it arrives.
unknown charset         bytes as they are (C2): ASCII words are found, and the rest reads as U+FFFD, which N5
                        folds into a space. No guess is made, since a guess is a table of its own to pin.
wrong charset label     decoded as labelled: that part's text is indexed as the wrong characters and its true
                        words are not found in it. Another alternative, if it is labelled right, is found. An
                        HTML part's own <meta charset> is not read.
iso-2022-kr, hz-gb-2312 the Encoding Standard decodes these to one U+FFFD. Here they pass as bytes (C2), so the
                        ASCII in them is found.
a writer on old rules   a build from before SEARCH-M10-42 writes entries that differ on the classes of 11.1; a
                        reader with the text reports index_mismatch and uses its own. After the format freezes
                        at M10's exit, any change to a rule of 11.2 is extractor 2 and a rebuild beside i1
                        (§11.14's rebuild row).
other tables            a build linking another Unicode or x/text writes nothing and reads status update (landed)
a request over a cap    never sent: the search stays on the device (Z5)
a hit over a cap        the builder leaves it out, as a receiver would (Z8 f), and counts it; building a reply
                        cannot fail, so no small Error follows a parsed request
a body not its one      INVALID from an indexer; no reply to a requester, which fails over (Z8)
  encoding
```

### 11.6 The test plan

**The conformance vectors**, `sidecar/testdata/index/conformance/`:

```text
mail.json      320 messages, each with its documents: fields 1, 2, 3 and 5 before normalization, the normalized
               text, the key count and the row. By rule group, a vector counting once for each group it
               pins: header block 28, encoded words 42, parameters 36, charsets 71 (40 of them one sample
               through each encoding), the walk 31, multipart bodies 21, transfer encodings 32, tags 39,
               references 26, documents and chunks 28 with file.json's.
file.json      40 files, 35 of them on the sniff and the title: binary or text, field 4, the chunks, the row
entities.json  the 2,231 named references
charsets.json  the 228 labels and their 40 encodings
sizes.json     85 rows of (size, content): sized or not, the pad's length and its varint's; and 7 whole
               bodies, each with its content bytes and the SHA-256 of the body
```

- **How they were made.** The inputs were written by hand, one or more for each rule and each "otherwise" of 11.2, and include every example of 11.1 and the six cases `testdata/index/extract/` already pins. The outputs come from the reference implementation of 11.3. For 306 of them the expected field or verdict was also written by hand and compared.
- **How they are kept.** They are data, with their inputs inside them. No implementation rewrites them: `SIDECAR_WRITE_VECTORS` does not reach this directory. A change to a rule of 11.2 changes this section, `INDEX-FORMAT.md`, the vectors and both implementations in one change, by hand.
- **How both implementations pass them.** Each runs every vector through its own entry points and compares every value the vector gives: `indexExtractMail` and `indexExtractFile` with `IndexDocument.prepare` in the root (`evs_index_conformance_test.go`, SEARCH-M10-42), and `searchOracleMailDocuments` and `searchOracleFileDocuments` in `sidecartest` (`search_oracle_conformance_test.go`, SEARCH-M10-43). A value given as `len` and `sha256` is compared that way. Each also checks its own copy of the reference table against `entities.json`, name for name, and that its label lookup gives `charsets.json`'s encoding for each label and nothing for a label outside it.
- **Every leg.** SEARCH-M10-41's runner reproduces `testdata/index/` on each leg, this directory included. The 32-bit legs matter here: P3's sections and E1's numbers are the places an integer's width could have shown.

**The cross-implementation check** (SEARCH-M10-43, under `sidecar_testhooks`): `FuzzExtractOracleEqualsIndex` in `sidecartest` takes any bytes as a message and as a file, and requires the oracle's documents and the index's, reached through the seam `sidecar.TestHookIndexExtract`, to be equal: count, fields before normalization, rows. Its seeds are every vector under 64 KiB. `TestExtractOracleEqualsIndexOnCorpus` does the same over `SearchCorpus`'s generated mail and notes. The oracle's import check stays: the seam is called from the test file, never from an oracle file.

**Fuzz targets.**

```text
FuzzIndexExtractMail, -File        landed: total; fields within 4 x the input + 1,024 B, which R3's 3.6 keeps;
                                   seeds gain every vector
FuzzIndexExtractAttachment         landed: no attachment byte in a field (R5)
FuzzExtractOracleEqualsIndex       new: the two implementations agree on everything (R2)
FuzzIndexExtractStreamEqualsWhole  new, SEARCH-M10-44: for any input and any split of it into writes, the
                                   one-pass form's keys and rows equal the whole-value form's (R4)
FuzzSearchRequestBody, -ReplyBody  §22.6's target, SEARCH-M10-31: parsing is total and memory-bounded; a body is
                                   accepted only if Z8 holds; an accepted body marshals back to itself
```

**Unit tests for sizes** (`search_remote_wire_test.go`, SEARCH-M10-31), each a top-level test and each one of 11.3's runs:

```text
TestSearchPadFillsEveryGapButFour     every pad length 1 to 70,000 through the marshaler; Z2 against it
TestSearchAdmissibleIsSound           every content at the five sizes
TestSearchCapBounds                   the marshaler's sizes at the caps: 3,778, 36, 7,578, 3,248, 90
TestSearchRequestSizes                every query length 0-512 with every repo count 0-64, filters none and at
                                      3, 126, 127, 128 and 768 B
TestSearchReplySizes                  seeded random replies at each step count; the kept hits a prefix
TestSearchReplyOnTheGap               the built replies of 6, 11 and 17 hits at two, three and four steps
TestSearchBodyIsItsOneEncoding        Z8's refusals: a non-zero pad, an unknown field, pad twice, a long varint,
                                      fields out of order, a wrong size
TestSearchSizeVectors                 sizes.json, row by row and body by body
```

FS-83's size cases stay as planned (0, 1 and 20 hits, TOO_BROAD, INVALID, CURSOR_EXPIRED, UNSUPPORTED_VERSION) and gain a reply on the gap at two steps. FS-76 gains the vectors' messages in its corpus (11.7).

**Mutants.** Each of these, put back, must fail a vector, and the landed code is the proof that it does: the library's quoted-printable reader (`t-qp-long-line`, `t-qp-control-bytes`), its base64 (`t-base64-unpadded`), `html.UnescapeString` (`e-one-digit`, `e-overflow`, `e-two-code-points`), `strings.TrimSpace` and `strings.ToLower` (`h-value-nbsp-stays`, `h-name-ascii-case-only`), `strconv.Atoi` (`p-section-signed`), no HeaderMax (`h-cap-line`), no LineWindow (`b-line-past-window`). For sizes: a pad computed by trial that stops at a gap (`TestSearchReplyOnTheGap`), and a receiver without Z8 (d) (`TestSearchBodyIsItsOneEncoding`).

### 11.7 Implementation notes, task by task

Order: SEARCH-M10-42 and SEARCH-M10-43 at once, by different authors (D-TEST-14). SEARCH-M10-31 at once; it shares nothing with them. SEARCH-M10-44 after SEARCH-M10-42. SEARCH-M10-36 after SEARCH-M10-42 and SEARCH-M10-43, with its other needs. All are the data lane's. Entries for the three new tasks are in `.stack/plan/proposals/details-11-tasks.md`.

**SEARCH-M10-31, remote search's wire** (held; M; its Build line changes). Build Z1 to Z8 in `search_remote_wire.go`. Proposed names: `searchRemotePadByteCount(bodyByteCount, contentByteCount int) (int, bool)` is Z2; `searchRemoteAdmissible` Z3; `searchRemoteBuildRequest` Z5; `searchRemoteBuildReply(steps int, hits []*protocol.SearchHit, head func(hitCount int) *protocol.SearchReply) ([]byte, int)` Z6, returning the body and how many hits it took; `searchRemoteFailureReply` Z7; `searchRemoteParseRequest` and `searchRemoteParseReply` Z8, the first returning the status to answer with. Landed code that changes: in `rpc_search.go`, `padSearchReply` loses its loop over five pad lengths and takes its length from `searchRemotePadByteCount`, keeping `errSearchReplySize` for a content that is not admissible; `searchInvalidReply` builds Z7's reply through it, and its output for the landed tests does not change. The plan's "a request over budget splits by repo" goes: under Z4 no request is over budget. Traps: take the content with `proto.Size` after clearing `pad`, never from a previous marshal; `head` must be a pure function of its count, since it is called up to 21 times, and it is where `checked_through_ms` is computed for the hits kept, which is the plan's own trap; apply Z8 (f)'s dropping to the builder's own hits first, so that building cannot fail; in Z8 check the version before (d); a parsed request is never answered with an Error. Tests: 11.6's.

**SEARCH-M10-36, results against the oracle** (held; L; its Needs and corpus change). The schedules are as planned. Its corpus gains every conformance vector under 64 KiB as a document, at fixed days of the 200, and its query set gains terms that only the canonical reading finds: a word a soft line break joins, a name from RFC 2231 sections, a word after a 4,096 B quoted-printable line, a word behind `&#9` and one inside an unpadded base64 tail. So FS-76's "the desktop's hits checked against its own text equal the oracle's" is exercised on the inputs of 11.1, which the generated corpus never reached. It needs SEARCH-M10-42 and SEARCH-M10-43: on the landed extractors those documents fail it, at the nine vectors of 11.1 A.

**SEARCH-M10-42, extractor 1 to the canonical rules** (new; M). The landed code that changes, by file:

```text
evs_index_extract_mail.go  indexSplitMailHeader: names and values by lower and trim of bytes (H5), HeaderMax
                           (H4); the joined values cut (H6)
                           indexDecodeCharset: the label's bytes, and utf-8 and replacement left alone (C1, C2)
                           indexDecodeEncodedWord: base64 by W3, with no skipped CR
                           indexParseMediaValue: lower and trim of bytes; a section is 1-9 digits (P3)
                           indexMultipartParts: LineWindow (B1)
                           indexTransferDecode: selects by T1 and calls the two decoders below
                           the imports of encoding/base64, encoding/hex, mime/quotedprintable and strconv go
evs_index_extract_transfer.go   new: indexBase64Body (T2) and indexQuotedPrintable (T3)
evs_index_extract_html.go  indexStripHtml keeps X1-X7 as landed and ends in indexDecodeReferences (E1-E4); the
                           import of html goes
evs_index_extract_entities.go   new: the 2,231 names, generated from entities.json and checked against it
evs_index_sniff.go         indexSniff: S3
evs_index_document.go      no change of bytes: field 4 is already the title, a space and the path. Its comment
                           and evs_index_extract_mail.go's lose "pending question".
protocol/INDEX-FORMAT.md   Extractor 1 and Documents become 11.8's text
```

The 29 vectors the landed code fails are its list of work: `h-value-nbsp-stays`, `h-name-ascii-case-only`, `h-cap-line`, `h-cap-fold`, `h-cap-join`, `w-b-carriage-return`, `p-section-signed`, `p-section-ten-digits`, `b-line-past-window`, `t-base64-stops-at-garbage`, `t-base64-unpadded`, `t-base64-one-pad-of-two`, `t-qp-control-bytes`, `t-qp-long-line`, `t-qp-trailing-whitespace`, `t-qp-cr-without-lf`, `t-qp-padding-past-window`, `c-label-not-ascii`, `c-replacement-passes`, `c-replacement-empty`, `c-sweep-replacement`, `e-two-code-points`, `e-one-digit`, `e-one-digit-at-end`, `e-no-digits`, `e-overflow`, `s-utf-8-mark`, `s-utf-8-mark-only`, `s-utf-8-mark-twice`. Five of them (the three `h-cap-`, `t-qp-trailing-whitespace` and `s-utf-8-mark-twice`) change a field's bytes and not its entry. `testdata/index/extract/vectors.json` keeps its bytes: the reference gives the landed output for all six. It also adds the seam `TestHookIndexExtract` under `sidecar_testhooks`, which returns each document's chunk number, its five text fields as the normalizer is given them and its row's values. Traps: write the decoders as the rules read, byte loops with no regular expression and no library decoder, since the point is that nothing outside this repository can change them; the table is data, so generate it and test it against the file rather than typing it; `lower` and `trim` are of bytes everywhere, and `bytes.EqualFold`, `strings.ToLower` and `strings.TrimSpace` have no place in these files; keep `indexDropsMarks` and the normalizer untouched.

**SEARCH-M10-43, the oracle's extractor to the canonical rules** (new; M; another author than SEARCH-M10-42's). `sidecartest/search_oracle_extract.go` is brought to 11.2 from this section and `INDEX-FORMAT.md`, sharing nothing with the index: its own base64, quoted-printable and reference decoders and its own generated copy of the table (`search_oracle_entities.go`). The 38 vectors it fails are the index's 29 and the 9 where it read differently: `x-script-end-name` (X5), `t-base64-nbsp-stops` (T2), `w-charset-with-space` (W2), `w-nbsp-between` and `w-cr-between` (W6), `p-sections-without-zero`, `p-sections-empty-fall-through` and `p-sections-repeat` (P3, P5), `b-unterminated` (B4). `searchOracleDocument` keeps its fields before normalization, for the cross check. It adds `search_oracle_conformance_test.go` and the cross-implementation fuzz target and corpus test of 11.6. Trap: the oracle may not take the index's table or decoders to save work; `TestSearchOracleImportsNoIndexCode` must keep failing on that.

**SEARCH-M10-44, extraction in one pass** (new; L). Build 11.2.8 in new files (`evs_index_extract_stream.go` and beside it): a message is written to it front to back in pieces of any size, and it hands each finished document to the caller as its key set and row, never as text; a file is read through an `io.ReaderAt`. The whole-value functions stay, as the form the vectors and the oracle are compared with and the form the fuzz target holds this one to. Writers call the one-pass form on every host once it lands (SEARCH-M10-13 and SEARCH-M10-14, which problem 1 holds). Tests: every conformance vector, written in one piece, byte by byte and in random pieces; `FuzzIndexExtractStreamEqualsWhole`; a generated 50 MiB message of each of 11.4's shapes with the heap sampled at each document, its growth over the normalizer's own staying under 256 KiB whatever the message. Traps: hold a line break back until the next line is known not to be a delimiter; test a line against the boundaries outermost first; never buffer a part to learn its length; one key bitmap at a time, the 256 B overlap replayed into the next document.

**Tasks not held that this touches.** SEARCH-M10-41's runner needs no change to reach the new directory; its report should name the 32-bit legs for it. SEARCH-M10-06 and SEARCH-M10-07 are drafted, and their extract files are finished by SEARCH-M10-42 and SEARCH-M10-43. SEARCH-M10-32 calls `searchRemoteBuildReply` with its own `head`, and answers every failure after parsing through `searchRemoteFailureReply`. The index document's other pads do not change: normalizer 1's one space each side of a field (`indexFieldPad`, N7) and a shard's keyed pad (`evs_index_pad.go`) are as landed.

### 11.8 Proposed DESIGN.md text

**§11.14, Documents, the extract row.** Replace the row: "extract   extractor 1, every byte of which protocol/INDEX-FORMAT.md fixes and testdata/index/conformance/ pins; it calls no library parser, reads damaged input by rule and refuses none; mail: the message's own Subject, From, To and Cc values with RFC 2047 words decoded (fields 1, 2 and 3, To before Cc), and in field 5, in the message's order and joined by one space, each part's name and each text/plain and text/html part's text, MIME-decoded (RFC 2045, 2231), HTML with its tags, scripts and styles removed and its character references decoded; every alternative is read, an attachment gives its name alone, and multiparts are read 16 deep; never transport headers, attachment bytes or base64; files: the title is the first line holding a letter or a number, without its heading marks, at most 80 B; field 4 is the title, a space and the path, and field 5 the text; records: §16.8's mapping of an entry's sealed body; every chunk of a document carries its fields 1-4; the extractor's id is in every file header".

**§11.14, Documents, the sniff row.** After "or it opens with a UTF-16 byte-order mark and is decoded": "; a UTF-8 byte-order mark is dropped".

**§11.14, Files and format, the determinism row.** After "no clock, randomness or library-version input": "; extraction's base64, quoted-printable, character-reference, header and multipart readings are the format's own rules, and no library's parser is part of them".

**§11.14, search.proto.** `SearchFilters`: "// <= 768 B as encoded in a SearchRequest". `SearchCoverage.chain`: "// <= 32 B". `SearchHit.correction`: "// near: the corrected term, <= 256 B". The `pad` comments stand.

**§11.14, the sizes row.** After "failures after parsing included;": "a body is the one deterministic encoding of its message, pad last; every other field stops at the body's size less 131 B, so pad's length takes two bytes or three, and a reply whose other fields would leave exactly 16,387 B returns the most hits, at most 20, that leave another gap;".

**§11.14, the status row.** INVALID's list becomes: "(a wrong size, a body that is not its message's one encoding or holds a field this version does not know, a non-zero pad, a query over 512 B or 16 terms, over 64 repos, filters over 768 B or malformed, a later page carrying page 0's fields)". UNSUPPORTED_VERSION gains: "judged before the encoding, so a later version's fields are not INVALID".

**§11.15.** A row: "Index extraction | one pass in fixed memory on app hosts: at most 132 KiB beyond normalizer 1's buffers and one key bitmap, whatever the message".

**§11.17, D-EVS-44.** After "byte-exact determinism": ", extraction included: extractor 1 is specified to the byte and calls no library parser".

**§11.17, D-EVS-59.** After "failures after parsing included": ", each body the one encoding of its message".

**§16.10, filters.** "A remote request carries at most 768 B of encoded filters; a search with more stays on the device, with fallback reason none." (QD-215, restated where §16.10 lists them.)

**§22.12, D-TEST-14.** Add: "The oracle's extractor and the index's are held to one set of conformance vectors and to equality under a fuzz target, since on damaged mail two readings of the same rule are the likeliest way for the two to differ."

**§22.6.** The every-body target's `SearchRequest` and `SearchReply` line gains: "a body that is not its message's one encoding is refused". A line for extraction: "**Extractor 1** (messages and files): total; fields within four times the input; the index, the oracle and the one-pass form equal on every input; no attachment byte in a field."

**§22.9's Index determinism row and §22.12's D-TEST-15.** `testdata/index/`'s list gains "extraction (mail, files, the character-reference table, the charset labels) and search body sizes".

**§22.8, FS-76.** After "MIME with base64, quoted-printable and HTML parts": ", and the conformance vectors' damaged messages". **FS-83.** After "UNSUPPORTED_VERSION": ", and a two-step reply whose content sits on the 16,387 B gap".

**§22.8, FI-22.** "a function of its format version, normalization version, extractor version and inputs alone".

**protocol/INDEX-FORMAT.md** (SEARCH-M10-42 writes it; `design-records` need not). Its Extractor 1 and Documents sections become 11.2.1's constants and tables and the rules D1-D6, S1-S4, H1-H6, W1-W6, P1-P6, C1-C3, M1-M6, B1-B4, T1-T3, X1-X7 and E1-E4 as written here, with 11.2.7's table. Normalizer 1 gains the three clarifications under 11.2.2. "What this file adds" gains a row for each reading 11.9 lists.

Nothing server-visible changes: no column, key, object family or proto field (I-18), and `search.proto`'s fields are sealed end to end.

### 11.9 Owner questions

Each is filed under `.stack/questions/`, and the design above is built on its recommendation.

**Extraction's own decoders (`details-11-own-decoders.md`; amends QD-474).** Both implementations call the standard library for base64, quoted-printable, character references, case and whitespace, and what those calls do on damaged input is not stated and can change with a Go release. Options: (1) every such reading is a rule of the format, as 11.2 has them, with HTML's reference table in the repository: about 400 lines in each implementation and some 40 KB of table on the legs that index; a Go release can no longer change an index, and four defects go (a quoted-printable part cut at a 4,096 B line or a control byte, a base64 tail lost, `&#9` unread, two of HTML's names unread); (2) keep the calls, and make the Go release part of extractor 1's identity, recorded in headers: any release that touches those packages is a new extractor and a rebuild of every index, and the defects stay; (3) keep the calls and write down what they do today: the rules then describe one release's accidents, the 32-bit sum among them. Recommended: 1. It replaces three sentences of QD-474: references are E1-E4 and not `html.UnescapeString`; a label is read as bytes; `replacement` labels pass as bytes.

**Extraction's limits (`details-11-extraction-bounds.md`).** Three readings need unbounded lookahead, so no one-pass extractor in fixed memory can be exact without a limit on each. Options: (1) HeaderMax 16,384 B and LineWindow 1,024 B as 11.2.1 has them: a header value's tail past 16 KiB is not indexed, where fields 1-3 keep 1,024 normalized bytes anyway, and a delimiter line or soft line break with over 1 KiB of trailing blanks is read as text; no honest message meets either; (2) no limits: exact on any input, and an app host then holds the largest header value or line in memory, up to the message's 50 MiB, or reads the message from storage more than once; (3) larger limits, 65,536 B and 4,096 B: the same shape at four times the memory, 520 KiB, for inputs no mailer writes. Recommended: 1.

**A search body's one encoding (`details-11-body-encoding.md`).** Options: (1) a receiver refuses a body that is not the deterministic encoding of its message or that holds a field it does not know (Z8 d): the pad check is then complete and a message has one body; a later version's fields must ride a later `search_version`, which the indexer answers UNSUPPORTED_VERSION before it looks at the encoding; (2) accept whatever parses and check the `pad` it parsed: a later requester's fields 13 and 14 can reach an older indexer, which ignores them, and non-zero bytes can ride in a second `pad` or an unknown field, which only the two ends of the sealed session could use. Recommended: 1. The channel is between two devices that already share the session, so the gain is not secrecy; it is that "exactly these bytes" has one meaning, which the size tests and the fuzz target can state.

**Small readings (`details-11-small-readings.md`).** Ten readings that change no D- item, listed there by number: a file's UTF-8 mark is dropped (S3); names, labels and encodings compare under ASCII `lower` and only white bytes are trimmed (11.2.1); an unterminated multipart's last part keeps its last line break (B4); of two RFC 2231 pieces of one name, kind and section the first counts, and sections that join to nothing fall through (P3, P5); a section is 1 to 9 digits (P3); base64 decodes a last partial group (T2, W3) and an encoded word's base64 skips nothing; quoted-printable passes control bytes and has no line limit (T3); a numeric reference needs one digit, `&#x;` is text and a number past U+10FFFF is U+FFFD (E1); `SearchHit.correction` is at most 256 B and `SearchCoverage.chain` at most 32 B (Z4); extractor 1 keeps its number (11.2). Options: accept all, or correct any by number. Recommended: accept all.

**Existing questions this section answers.**

- `search-m10-05-extractor-unstated-bytes`: its option 1, and further. Where the two differed, the index's reading is the rule in every case (X5, T2's white bytes, W2, W6, P3, P5, B4). Where both leaned on the library, the rule is 11.2's own (the first question above).
- `search-m10-07-extractor-field-placement`: its option 1 (D2, D3, D4).
- `plan-SEARCH-exact-body-sizes`: decided by the owner as QD-215, which stands. This section makes it exact (Z1-Z7), adds the receiver's rule (Z8) and the two caps its proof needs (Z4).
- `plan-SEARCH-index-format-bytes` #8 (QD-474, a proposed fill): stands but for the three sentences named above. `plan-SEARCH-cherokee-fold` (QD-256), `plan-SEARCH-small-readings` #1 and #2 (QD-596, QD-387): stand, and N3 and D4 restate them.

## 12. Bridge compiler and NAT engine (§17)

Status: pending

Tasks held until complete: BRIDGE-M4-16, BRIDGE-M4-17, BRIDGE-M6-03, BRIDGE-M6-04.

## 13. Smaller scheduling problems: closure pacing, quota leases, socket registration

Status: complete (2026-11-10)

Tasks held until complete: QUOTA-M2-07, SOCK-M5-05, SOCK-M5-06, SOCK-M5-07.

Models: `sidecar/sidecartest/model/details/Pacing.tla` (closure pacing), `Lease.tla` (edge leases on one balance) and `SockReg.tla` (one registration against revocation), their configurations (`Pacing*.cfg`, `Lease*.cfg`, `SockReg*.cfg`) and `run-sched.sh` beside them. New tasks: `.stack/plan/proposals/details-13-tasks.md` (QUOTA-M2-14, QUOTA-M2-15, SOCK-M5-18). Questions filed: `.stack/questions/details-13-pacing-seats.md`, `details-13-lease-lapse.md`, `details-13-lease-draw-size.md`, `details-13-gate-behind.md`, `details-13-edge-pair-life.md`, `details-13-metadata-rows.md`. Questions this section answers, each as 13.9 says: `quota-m2-03-pacing-boundary-order`, `quota-m2-01-rate-key-grammar` #3.

### 13.1 The problem

Three mechanisms state their outcome in DESIGN.md and leave the order of events to chance: which eraser's ask reaches Redis first, whether a host's reading of a balance is older than the debit that changed it, and whether a registration's write lands before or after the revocation that should have stopped it. Each has a schedule that breaks the stated outcome today.

**A. Closure pacing admits by arrival (question quota-m2-03-pacing-boundary-order).** §20.7's closure and wait rows promise that, at the storage limit or while spent, a network takes at most R = 4 `?closure=1` uploads a second "in equal turns: with k of the network's erasers asking for one ... each takes one at most every k/R s", and FS-47 asks for "k erasers asking each served every k/4 s, none starved ... including the 00:00 UTC stampede". The landed mechanism (reading 19; `sidecar.QuotaClosurePacing` and the `{sq_}` script that mirrors it) gives each asking eraser a slot on a tail spaced 1/R apart, keeps a slot for 5 minutes past its turn, and lets a bucket of R a second decide between erasers whose slots have all come due. The bucket admits whoever asks first.

1. *The stampede.* Twelve erasers were refused for their allowance at 23:59:30 and each holds a slot from then. At 00:00:00 all twelve are past due and ask in the same order each time. Four take. Their new slots are `max(tail + 250 ms, now)`, which is now, now + 250 ms, + 500 ms and + 750 ms, because the tail lies in the past. The eight refused are told the next second. At 00:00:01 all twelve are past due again, the same four ask first and take, and so on: the question measured 31 uploads each for the first four in 30 s and none for the other eight. The tail advances exactly one second a second, so a winner's next slot is always inside the second it won in. `Pacing.tla`'s `PacingTwin-Arrival` reaches an obedient eraser still waiting more than 32 cells (16 s at its R = 2) after its ask, and nothing bounds it.
2. *A late competitor.* The question's option 2 sends an eraser the bucket refused to the tail. Then an eraser that always arrives one second late, at the start of a second, takes that second's capacity before the erasers whose slots lie inside it, and each of those loses its place and waits another k/R. Two late erasers starve an obedient one for as long as they keep it up (`PacingTwin-Tail`, the same 32 cells).
3. *An upload that can never be retried, found here.* The script records a call's first answer under its debit id for 48 h, a refusal included (QUOTA-M2-03's "a replay of `debitId` answers its first result"), and the landed upload route derives the debit id from the segment and the sidecar alone (`evsservice/upload_segment.go`: SHA-256 of a domain, the segment id and the sidecar id). An upload asked before its turn is refused with `retry_after_ms` 250. Its retry carries the same debit id and reads the recorded refusal, whatever the pacing says by then, and so does every retry for 48 h. With two erasers asking, the second can never upload the segment it first asked for. Question quota-m2-01-rate-key-grammar #3 named the trap, and the route fell into it.

The requirement: the network takes at most R uploads in any second whatever asks arrive and in whatever order; an eraser that asks when it was told to takes within a bound that depends only on how many erasers hold a place, never on what the others do; a place nobody uses costs the others one upload's time and blocks nothing; and an upload refused for its turn can be asked again under the same id and is charged once.

**B. Leases have a protocol only in outline.** §20.6 draws a lease reserving 64 MiB at a time on "escrow's per-balance Redis reservations", spending with no I/O, sending a `UsageBatch` every 60 s and releasing at close. QD-087 decided how a spent byte meets its reservation (the host carves it out of the lease's token into a token named for the journal row, which the flush releases), and QD-055 decided that a host with no Postgres reads a payer's balances from api and reserves "straight to Redis". Four things are still open, and each can overdraw a balance or bill a byte twice.

1. *A reading older than a debit.* The reservation script takes the balance's credit as an argument and grants `credit - reserved`. api reads the credit a moment before it calls. An edge reads it through api and caches it. Balance B holds 100 MiB. Edge E1 reserves 64, spends them, carves and posts; the flush debits B to 36 and releases the carved token, so Redis holds no reservation. Edge E2 read the credit as 100 five seconds ago and now asks for 64: the script grants `100 - 0`, and E2 spends 64 MiB of a balance that holds 36. `LeaseTwin-NoFloor` reaches it in under 20 states.
2. *A carve that runs twice.* A host retries a carve whose answer it did not get. If both copies run, the second after the flush released the batch's token, the bytes leave the lease's token twice: the host believes it holds bytes Redis has given to someone else (`LeaseTwin-BlindCarve`).
3. *A host cut off from Redis.* Its tokens reach their expiry while it holds them in memory. If it keeps spending and later reports, the debit lands on bytes another host reserved meanwhile.
4. *A crash, anywhere.* Between a reservation and its answer, between a window's end and its carve, between the carve and the post, between the post and its answer. The design's loss row allows one window of bytes to go unbilled and nothing to be billed twice, and E-d wants the reservation back within its lease.

A fifth is a number. A Team endpoint may run at 1,000 Mbit/s (§20.4), 119 MiB a second, so a 64 MiB draw lasts half a second and its last quarter 134 ms, inside which the renewal must land or `Spend` answers false and the stream resets.

The requirement: every byte a lease debits was reserved on that balance when it was spent and is still reserved when its debit is journaled; no reading of a balance, however old, lets a reservation pass what the balance holds; a debit is journaled at most once and, barring a crash or a batch dropped at its horizon, exactly once; a dead host's reservations return on their own; and none of it needs Postgres on the host.

**C. A registration is judged once, by one process, at one position.** §9.5 re-checks each entry of each registration call against "the newest verified projection", §9.6 checks the dialer before a pick, and §9.8 has each process, on a revocation, delete "entries and pairs". The sockets processes are stateless and many (one block on every lb host), each with its own gate cache at its own position, and a registration and a Find are each two steps with Redis between them.

1. *A write that lands after the sweep.* Process P1 judges listener L's page at position n and allows it. Before its store call runs, entry n+1 revokes L's grant, P2 loads it, sweeps and deletes L's lease. P1's call then writes the lease afresh, for 45 s.
2. *A process that does not know.* P2's key event for n+1 is lost with its subscriber's connection. L, revoked and still asking, is answered `revoked` by P1 and `ok` by P2 on alternate heartbeats, and every `ok` is 45 s of lease. §8.9's 5-minute poll ends it, if P2's source answers; QD-055 lets P2 serve its last state for as long as the source does not.
3. *Find never asks about the listener.* Step 2 judges the dialer. Whatever lease the pick returns gets a ticket. For an application name the dialer re-derives the listener's grant itself (§9.6), but a `tls/` or `smtp/` dial comes from an edge that holds no config, so a revoked listener that any process still registers keeps receiving visitors.
4. *The pair outlives the revocation.* For edge names the `{svc_}` pair is the whole authorization of a Service contract (§6.10.1; platform clients skip the contract gate, §8.10), and it lives to the grant's expiry, up to 24 h. A Find that picked before the sweep and signs after it writes the pair again. A sweep that walks live registrations never meets the pair of a listener whose lease already ran out. Either way CreateContract keeps issuing contracts for a revoked listener's open streams for up to a day.
5. *An older page.* A page the client sent before its unlisten, delayed in a stalled store call, lands after it and re-creates the lease the newer page removed.

The requirement: no ticket is signed and no lease or pair is written by a process whose own verified position refuses it, or after the process has learned the log moved past what it holds; once any process has removed a lease or a pair for cause at position x, nothing admitted below x can be written in its place; a revoked or spent listener stops being found within a bound that is stated; and what a client's pages did to one name is what the newest of them says.

### 13.2 The design

#### 13.2.1 Closure pacing: seats

**A turn is a seat in one second.** Reading 19's shape stays: each asking eraser holds one place on a tail spaced 1/R apart, a refused ask keeps its place, and a taken turn takes a new place at the tail. Two rules change.

- *A seat is good from its instant to the end of its calendar second, and lapses with it.* There are no past-due seats, so nothing competes for a bucket.
- *A seat is handed out only in a second that still has a free cell*: the seats already in that second, plus what it has already taken if it is the current one, are fewer than R. The bucket is that count, kept true when seats are handed out, and it is never asked at admission.

An eraser whose seat is due takes. Nothing else is checked, so the order in which asks reach Redis decides only the order in which erasers with no seat are given one.

```text
state    {sq_<n>}closure_turns   zset: eraser (sidecar id) -> its seat, in µs since the epoch       (as landed)
         {sq_<n>}closure_pace    hash: tail (the latest seat handed out), second and taken (the uploads
                                 taken in that second), and clock, new: the latest time any call brought
consts   w = ceil(10^6 / R) µs, one cell; R = evs_closure_uploads_per_s, never below 4
         sec(t) = floor(t / 10^6); start(S) = S * 10^6

Ask(e, now_arg)                                     -- counts nothing; runs only if no counter of the call refused
  now := max(now_arg, clock); clock := now          -- one clock a network, which never runs back
  S := sec(now); if second != S: second := S; taken := 0
  ZREMRANGEBYSCORE turns -inf (start(S)             -- the seats of earlier seconds have lapsed
  seat := ZSCORE turns e
  if seat = nil: seat := NextSeat(now); ZADD turns seat e
  if now < seat: refuse {evs_closure_uploads_per_s, limit R, used taken, retry_after_ms ceil((seat - now)/1000)}
  else: pass                                        -- the seat is in second S and due

Take(e, now)                                        -- only when the whole call passes
  taken := taken + 1; ZREM turns e; ZADD turns NextSeat(now) e

NextSeat(now)
  c := max(tail + w, now); C := sec(c)
  used := ZCOUNT turns start(C) (start(C + 1)  +  (taken if C = sec(now) else 0)
  if used >= R: c := start(C + 1)                   -- no seat lies past the tail, so that second is empty
  tail := c; return c
```

All of it is inside the one `quota_rate` script a `CountRate` call already runs, on keys under the network's one hash tag, so it is atomic with the call's counters. `EraserCount`, k, is `ZCARD turns`.

**What the other counters do to a seat.** The call's counters (the eraser's own 60 a minute, its daily allowance) are judged first, and the pacing step runs only if none refuses. An eraser its own rate or allowance refuses is given no seat and keeps none alive: a seat is one upload's capacity, and an eraser that cannot upload must not hold it. This replaces the landed "asked even past a refusal". An eraser refused for its allowance until 00:00 UTC arrives then with no seat and is seated at the tail in the order it arrives.

**Debit ids.** The script records a call under its debit id only when the call passes. A replay of a passed id answers pass and counts nothing, touching no seat. A replay of a refused id is judged afresh: a refusal counted nothing, so judging again can count nothing twice. This is the other reading of quota-m2-01-rate-key-grammar #3, and it is what lets the upload route keep one debit id an upload (segment id and sidecar id, as landed), so an upload whose answer was lost is charged once and one refused for its turn can come back.

**Clocks.** Windows and seats are read on the caller's clock, which evs passes in. Two evs processes a few milliseconds apart would otherwise flip `second` back and forth at a boundary and reset `taken`. `clock` makes the network's time the highest any caller brought. A caller behind it is treated as arriving at it; one ahead of true time lapses seats early by its lead, which costs their holders a turn and breaks no bound, and §19.6's clocks row holds an evs host within 50 ms of true time.

**What an eraser sees.** A refusal's `retry_after_ms` runs to its seat's instant, and the seat is honored if the ask reaches the script before the seat's second ends: between 250 ms and 1 s of tolerance at R = 4, by the cell. An eraser's client therefore warms its connection before the instant and sends at it. One that misses its second has no seat when it next asks and is seated like a newcomer: in the current second if a cell is free, which is the usual case since a network with a handful of erasers is not full, else at the tail, one round later. Hammering gains nothing: an ask before the seat is refused with the same instant, and an eraser holds one seat at a time.

**Steady state is unchanged.** With k erasers asking all the while, seats are consecutive cells and each eraser's turns are exactly k·w apart, as today, and `TestClosurePacingServesKErasersEveryKOverR` is kept as written. A lone eraser takes R a second. In a stampede the first second's cells go to the first askers, each later asker is seated behind them, and every eraser then turns once a round.

#### 13.2.2 Leases

**Tokens.** A lease is one process's hold on one (network, meter). It owns reservation tokens on the payer's balances, all in the existing per-balance hash under `{escrow_<balance_id>}`, the "own namespace" §20.15 asks for:

```text
lease/<lease_id>/<n>   draw n of a lease: bytes reserved and not yet carved. lease_id is 16 random bytes drawn
                       when the lease opens, n counts its reservations from 1. Lifetime TokenTtl, 15 min,
                       extended while the lease lives. It never grows: carve and settle only shrink it.
svc/<usage_id>         bytes carved for one journal row: the debit's reservation until the flush releases it
                       (QD-087). Lifetime 24 h, redisContractReservationLease.
```

Neither carries a pending or recovery marker, so the recovery page never enrolls one, and a token nobody releases returns at its lifetime with no debit (E-d).

**The script** is `redisContractReservationScript`, with three new operations and one optional seventh key. Everything is on one balance's slot.

```text
KEYS[7]  {escrow_<balance_id>}approx_floor   optional; callers that pass six keys behave as today
         the lowest credit any caller showed within FloorTtl (2 min), a decimal string with that PX

floor rule, for every reserving operation called with KEYS[7]:
  credit := min(ARGV[3], GET KEYS[7] or ARGV[3])
  if KEYS[7] is absent or holds more than ARGV[3]: SET KEYS[7] ARGV[3] PX FloorTtl   -- lowered, never raised

reserve          as today, under the floor rule. A retry under the same token name answers the token's amount.

extend           ARGV[2] token, ARGV[5] lease ms. If the token exists: ZADD KEYS[3] now + lease, answer its
                 amount. Else answer 0: the host learns its token is gone.

carve            ARGV[2] destination svc/<usage_id>; ARGV[4] the sum to move; ARGV[5] the destination's lease
                 ms; ARGV[6] the lease tokens' lease ms; then triples (source token, amount, expect).
                 1 if the destination exists: answer {1, its amount}. Nothing moves: an earlier try ran.
                 2 else if every source holds exactly its expect, and expect >= amount: each source shrinks by
                   its amount (HDEL and ZREM when it reaches 0, else its expiry is set afresh); the destination
                   is written with the sum and its expiry; total is unchanged. Answer {1, sum}.
                 3 else answer {0, 0} and write nothing: a source is gone or was already moved.

settle           as today: the token shrinks to ARGV[4] and the rest returns. A lease's close uses it.

release-debited  release, and the floor rule with ARGV[3] the balance after the debit, which the flush read
                 in the debit's own transaction. Both flushes use it for every token they release.
```

`carve` goes below the `local rawTotal=` line that `redisGrantProbeScript` cuts its prelude at. It compares amounts as the script's decimal strings, never through `tonumber`.

*Why expect.* A source token only shrinks, so the amount it held before a given carve never returns. A carve that arrives a second time, however late, finds either its destination (case 1) or a source below its expect (case 3), and moves nothing. The host is the only writer of its lease tokens, so it knows each one's amount exactly once its last operation was answered; when an answer is lost it repeats the same call, which is idempotent in every case above.

*Why the floor.* A balance's `balance_byte_count` only falls: every statement in `server/model` that updates it subtracts (the two journal flushes and the two legacy settlement branches). So every reading of it is at or above its true value at any later time, the lowest reading shown is the best bound Redis has, and a reading taken before a debit can only be too high. `release-debited` is one script: it removes the token whose bytes the debit just consumed and lowers the floor to the balance the debit left, so there is no instant at which Redis has forgotten the reservation and not yet learned the debit. A host uses a reading for at most `MaxCreditAge` (30 s) from the moment it asked for it, and the floor outlives any reading taken before it was set (`FloorTtl` = 2 min >= 2 × `MaxCreditAge`), so an expired floor leaves no older reading in use. A floor that expires is set again by the next caller. The floor is a bound, never a source: with no floor the script reads the argument as today.

The two flushes are `FlushServiceDebits` (lease and relayed debits) and `flushTransferDebitBalance` (contract debits). Each already subtracts in one statement and releases after its commit; each changes its `UPDATE` to `RETURNING balance_byte_count` and its release to `release-debited` with seven keys. api's contract admission keeps six keys and its own fresh reading. The legacy branches that debit synchronously (`settleEscrowWithOptionsInTx`, `ReconcileContractAtDeadline`) feed no floor; what a lease host can over-admit from them is bounded by `MaxCreditAge` of their debits on that balance, and they drain with the legacy escrows.

**Reading balances.** A lease reaches balances through `quotahost.BalanceSource`:

```go
// server/quotahost. The payer's in-window balances in escrowDrawLess's order, each with the credit read then.
type LeaseBalance struct {
	BalanceId       server.Id
	CreditByteCount int64 // balance_byte_count, 0 when it is negative
	IsCredit        bool  // team_credit: drawn last (D-QUOTA-9)
	EndTime         time.Time
}
type BalanceSource interface {
	// One read, never cached by the source. An error leaves the caller with what it holds.
	DrawOrder(ctx context.Context, networkId server.Id) ([]*LeaseBalance, error)
	// Marks the network spent (§20.6): model.MarkNetworkSpent, or api's internal route.
	MarkSpent(ctx context.Context, networkId server.Id) error
}
```

`NewLocalQuota` reads `model.LoadDrawOrderBalances`; `NewApiQuota` calls api's internal surface (QD-055; QUOTA-M2-11 names the routes). The lease set keeps each network's answer with the time it asked: a reservation uses an answer younger than `BalanceRefreshAge` (5 s) as it is, refreshes an older one first, and never uses one older than `MaxCreditAge`. All of this is on the lease set's own goroutines, never on `Spend`.

**The host's state.** One `quotaLeaseSet` a process. An entry per (network, meter):

```go
type quotaLeaseEntry struct {
	leaseId   server.Id
	available atomic.Int64 // what Spend may take
	spent     atomic.Int64 // every byte Spend took, ever
	// the rest under stateLock, which is never held across I/O and never taken by Spend
	stateLock   sync.Mutex
	draws       []*quotaLeaseDraw // one per live token
	carved      int64             // bytes of spent already attributed to a batch, or given up
	handleCount int
	closed      bool
}
type quotaLeaseDraw struct {
	balanceId      server.Id
	rank           int       // the balance's place in draw order when drawn
	token          string    // lease/<lease_id>/<n>
	amount         int64     // what the token holds, as the host last learned
	spendableUntil time.Time // on the host's monotonic clock; see expiry
}
```

`Spend(n)`: a compare-and-swap loop that takes n from `available` if it holds n, then adds n to `spent`. No lock, no I/O, no allocation. False when `available` is short.

`Lease(ctx, networkId, meter)`: an open entry that holds bytes gives a new handle with no I/O. An open entry that holds none makes one draw now, and an absent one is opened with its first draw. A draw that reserves nothing while Redis answered is a `QuotaRefusal` (limit key `data`, `upgrade`, as quota-m2-03-readings #3) with `MarkSpent`; Redis unanswered is an error, with no refusal and no mark. The draw's size on Community comes from the network's cached `QuotaLimits.Tier`.

```go
// server/quotahost. DefaultLeaseSettings is the only source of a default.
type LeaseSettings struct {
	DrawByteCount          int64         // 64 MiB
	CommunityDrawByteCount int64         // 16 MiB
	DrawMaxMultiple        int           // 16: a draw is at most this many times the above
	DrawAhead              time.Duration // 4 s of the lease's rate
	RenewAhead             time.Duration // 2 s of the lease's rate
	RenewFraction          float64       // 0.25: or when this much of the last draw is left
	TokenTtl               time.Duration // 15 min
	ExtendInterval         time.Duration // 5 min
	ExpiryMargin           time.Duration // 30 s
	CarvedTokenTtl         time.Duration // 24 h, redisContractReservationLease
	BalanceRefreshAge      time.Duration // 5 s
	MaxCreditAge           time.Duration // 30 s
	FloorTtl               time.Duration // 2 min; Validate refuses less than twice MaxCreditAge
	ReserveRetryCount      int           // 3
	CallTimeout            time.Duration // 1 s, redisContractAdmissionTimeout
}
```

*Draw.* For a draw of D bytes the entry walks the payer's balances in draw order, and on each calls `reserve` for what is still wanted under a new token name, until D is reserved or the balances end. Each call is its own slot, so a draw over two balances is two calls and is not atomic: a host that dies between them leaves a token that lapses. Each granted amount becomes a draw, and its bytes join `available` when its answer arrives. A call with no answer is repeated under the same token name, which answers the token's amount; after `ReserveRetryCount` (3) tries the name is abandoned and its token, if any, lapses.

*Attribution.* Spent bytes are attributed to draws only when a batch is planned, in rank order, the lowest rank first and within a rank the oldest draw, whatever order the draws were made in. So a lease that drew on the credit line and later, when a data pack regained room, on the pack, spends the pack's bytes first, and what is unspent at close is the highest ranks' (E-a, E-b). The invariant the host keeps: the draws' amounts sum to `available` plus the bytes spent and not yet planned into a batch plus the bytes of planned batches not yet carved.

*Renewal.* A goroutine per entry, woken by `Spend` through a non-blocking send when `available` falls below the renew mark. Mark: the larger of a quarter of the last draw and `RenewAhead` (2 s) of the entry's spend rate, measured over the last second. Draw size: `DrawByteCount` (64 MiB, 16 MiB on Community) or, when larger, `DrawAhead` (4 s) of that rate rounded up to a multiple of it, at most 16 times it (1 GiB; 256 MiB on Community). A slow lease behaves as §20.6 draws it: 64 MiB, renewed at 75% used. A renewal that reserves nothing while Redis answered leaves the lease to run dry, and when `Spend` first answers false the entry calls `MarkSpent` once. A renewal Redis did not answer is retried with backoff and marks nothing: `Spend` answers false when the draws run out, and the edge resets, which is the closed direction.

*Expiry.* Every draw carries `spendableUntil`: the host's monotonic time just before it sent the token's last answered `reserve`, `extend` or `carve`, plus `TokenTtl`, less `ExpiryMargin` (30 s). A ticker a second extends each draw every `ExtendInterval` (5 min). An `extend`'s answer replaces what the host holds as the token's amount, which settles a carve whose answer never came. A draw that reaches `spendableUntil`, or whose `extend` answers 0, is dropped: its unspent bytes leave `available`, and its spent bytes not yet in a carved batch are given up, added to `carved` and counted in `urnetwork_quota_lease_unbilled_bytes_total`. The host therefore stops spending a token's bytes at least the margin before Redis can give them to anyone else, whatever its reach to Redis.

*A batch.* `quotahost`'s `ReportUsage` receives the engine's batch (its events as the engine counted them, its id fixed by QUOTA-M2-01's batcher) and, before it sends it:

```text
plan     once per batch id, kept with the batch through its retries: for each event on a lease meter, take
         min(event bytes, spent - carved) from the entry, attribute it to draws in rank order, and group by
         balance: usage_id = model.ServiceUsageId(batch_id, network, meter, balance), with the list of
         (token, amount). carved rises by what was taken.
carve    one script a balance. Each source's expect is the token's amount as the host knows it when the carve
         is first sent, and every retry repeats it. {1, sum}: the draws shrink by their amounts. {0, 0}: the
         sources are gone; the part is dropped from the plan, its bytes are counted unbilled, and its draws
         are dropped as expired. No answer: repeated with the same arguments on the batcher's backoff.
post     only when every part of the plan is carved or dropped: the batch with its UsageCarve rows, each
         lease meter's event carrying the sum of its carved parts and no more, to model.ApplyUsageBatch or
         api's route. Retried under the batch's id for the batcher's 10 minutes.
give up  at the horizon the batch is dropped, counted and alerted as today. Its carved tokens are left alone:
         the post may have been applied, and then the flush releases them; if not, they lapse at 24 h.
```

*One operation a token at a time.* The operations that name one lease token (`reserve`, `extend`, `carve`, `settle`, `release`) are sent one at a time, each only when the one before was answered, so the host knows the token's amount whenever it computes the next. An operation that goes unanswered is repeated as it was. If it is abandoned, as a carve is with its batch at the horizon, the token's next operation is an `extend`, whose answer is the token's amount. Two batches of one lease therefore carve in the order they were planned, and a close settles a token only after its carve in flight.

`ApplyUsageBatch` changes one rule: for the lease meters (`tls`, `mx`, `smtp`) an event's bytes must equal its carves' sum, else the batch is refused whole. Only `evs` bytes draw at apply.

*Close.* The last handle's `Close` marks the entry closed and zeroes `available`. Each draw, the highest rank first, is then `settle`d to the bytes still attributed or attributable to it (spent and not yet carved), or `release`d when that is none: the unused rest returns in reverse draw order, at once. The entry stays in the set until its last batch has carved what is left, and a `Lease` call for the same (network, meter) meanwhile opens a new entry with a new lease id. `Drain` flushes the batcher, which carves and posts, and then closes every entry.

**State machine of one token's bytes.**

```text
free --reserve--> lease/<id>/<n> --carve--> svc/<usage_id> --ApplyUsageBatch--> journaled --flush commit--> debited
                    |    |                     |                                             --release-debited--> gone
                    |    +--settle, release--> free     (close: the unspent rest)
                    +--expiry (15 min unextended)--> free   (a dead host, or one cut off: its spent bytes unbilled)
                                               +--expiry (24 h, never posted)--> free   (a host dead between carve and post)
```

#### 13.2.3 Sockets

**Positions.** Every verdict the engine acts on comes from one `AclGateSnapshot`, and carries its position n (the authorization log position of 5.2's S(n)). The gate is ACL-M2-13's `AclGateCache`, one a process (C-09), read through ACL-M5-01's `AclGateView` once that lands; section 5 governs what the cache verifies (the chain from its own pin, the base's tail bits, FORK on a difference), and nothing here re-reads an entry. What this section adds is around it: when a snapshot may be acted on, and what the store remembers of the position a write was allowed at.

**Evidence, and when a process is behind.** `gate_projection.go` wraps the cache's source and its triggers.

```text
evidence    that network N's log has moved past what this process holds:
            a key event on {acl_<N>}v; a store answer naming a position above the snapshot's (a lease, a
            tombstone or a pair floor a fresher process wrote); after a resubscription, a {acl_<N>}v that
            differs from the value recorded with the snapshot
record      the wrapped source's Entries call reads {acl_<N>}v first and notes, for the load it begins, that
            value and the evidence count at that moment; when the cache's OnLoad reports that load without
            error, the snapshot's version is that value and every evidence up to that count is covered
behind      N has evidence not covered. The first uncovered evidence starts a clock.
fresh       not behind, or behind for less than GateBehindGrace (5 s, §8.9's target for server gates)
rule        the engine acts on N's snapshot only while N is fresh. Otherwise every registration page and Find
            for N answers unavailable with retry_after_ms, and the gate answers ErrSocketGateBehind.
```

```go
// socketsservice/gate.go, added to what SOCK-M5-03 landed
var ErrSocketGateBehind = errors.New("socket gate is behind the network's log")

// One network's state at one position, immutable: what a page or a Find judges everything on.
type SocketGateView interface {
	// The authorization log position of the state: a lease's pv and a ticket's policy_version.
	Position() uint64
	MayListen(request *SocketGateRequest, now time.Time) *SocketGateVerdict
	MayDial(request *SocketGateRequest, now time.Time) *SocketGateVerdict
	MayPublish(request *SocketGateRequest, now time.Time) *SocketGateVerdict
	IdentityKey(sidecarId connect.Id) (publicKey []byte, found bool)
}

// SocketGate gains:
//	// The network's newest state while it is fresh. ErrSocketGateUnloaded, or ErrSocketGateBehind past the grace.
//	View(networkId connect.Id) (SocketGateView, error)
//	// Evidence from the store that the network's log reached position. Nothing at or below the state's.
//	Observe(networkId connect.Id, position uint64)
```

The landed `MayListen`, `MayDial`, `MayPublish` and `IdentityKey` stay, each a `View` and one call on it. Each evidence calls `AclGateCache.Changed`, so a load follows. The cache's own 5-minute poll stays, as §8.9 has it, and is no evidence: it loads, and if the log did not move nothing changes. The host does not call `AclGateCache.Watch`: the wrapper registers the one callback on `{acl_*}v`, which only notes the network for the wrapper's worker (a key-event callback does no I/O). On a resubscription the worker reads `{acl_<N>}v` for every loaded network in pipelined batches of 1,000 and treats only the differing ones as evidence, where `Resync` would reload them all.

A process with no source, or one that has never loaded N, is as today: not ready, or `ErrSocketGateUnloaded`. A network the cache holds nothing of is asked for at once and answers unavailable until its first load: every caller outside `urnetwork-edge` is a bound sidecar, so its network has a log, and `ur/` names, which `urnetwork-edge` holds, are judged by no state. A load the cache refuses with an alarm (a lower n, a second A_n, a broken link) covers nothing, so the network stays behind and, after the grace, unavailable at this process until a load succeeds: the log moved and this process cannot verify where to.

This narrows QD-055's "on failure the last verified projection keeps serving": it keeps serving while nothing says the log moved, which includes every api outage, since api is the log's only writer; it stops serving a network 5 s after evidence it cannot follow (question details-13-gate-behind).

**The store's records.** SOCK-M5-04's keys and scripts, with these additions.

```text
m:<L>      gains three fields at its end: sidecar (the listener's sidecar_id, hex, empty for ur/), pv (the
           position the lease was last admitted at, decimal) and sv (the set_version of the page that wrote it)
x:<L>      new, a tombstone: sv;pv;cause, with a field ttl. cause 1 a removal for cause (the gate refused it
           at pv: TombstoneTtl, 10 min); cause 2 the client was removed (pv is 2^64 - 1: 10 min); cause 0 an
           unlisten (pv 0: UnlistenFenceTtl, 60 s). A second tombstone on one field keeps the higher of each
           number and the longer ttl.
{svc_<L>}  gains the field ~f, the pair floor: a position, with TombstoneTtl
{sn_<N>}names   gains the field 0x00, "<pv>;<until_ms>": the newest position a revocation sweep claimed and
           until when. No name key is one byte, and a listing skips it.
```

The group script (`put`, `del`), one script on the group's slot:

```text
put(L, record, sv, pv)
  x := HGET x:<L>; m := HGET m:<L>
  if x and (pv < x.pv or sv < x.sv): return {fenced, x.pv}     -- a removal at a newer position or set stands
  if m and sv < m.sv: return {stale}                            -- an older page of the same client
  the taken check, as landed
  write m with pv := max(pv, m.pv if m), sv; HDEL x:<L>; lease and ix as landed
  return {ok, first_listener, ..., m.pv before the write or 0}
del(L, cause, sv, pv)
  m := HGET m:<L>
  if not m: return {absent}
  if cause = 0 and not (m.sv < sv): return {kept}               -- an unlisten older than the lease
  if cause = 1 and (m.pv > pv or m.sv > sv): return {kept, m.pv}  -- the lease was admitted past this verdict
  remove the listener as landed; write x:<L> = max of each with any x there, with the cause's ttl
  when no listener is left: DEL ix and HDEL v, and leave the tombstones to their ttls   (was: DEL group)
  return {removed, last_listener, ...}
```

A tombstone is written only when a lease was removed, so a refused entry that never held one leaves nothing. A removal that no page carries (the sweep's, a Find's) passes the lease's own sv. `TombstoneTtl` must exceed the longest a process can be stale without knowing it, the cache's poll and one load, 6 min. `Pick` and the read script return `m` whole, so they carry the three new fields with no change of their own.

The pair scripts, one script on `{svc_<L>}`:

```text
pair_set(dialer, grant_expire_ms, ttl_ms, pv)    if ~f and pv < ~f: return {0, ~f}; else HSET, HPEXPIRE: {1}
pair_remove(pv)                                  HDEL every field but ~f; ~f := max(~f, pv) with TombstoneTtl
pair_touch(ttl_max_ms, now_ms)                   each dialer field's ttl := min(its grant's remaining, ttl_max)
```

**A pair's life.** A `tls/` or `smtp/` pair stands for the listener's edge grant, so the listener's verified registration keeps it: Find writes it with a ttl of the lesser of the grant's remaining life and `EdgePairTtl` (15 min), and a registration call that accepts at least one edge entry of the client runs `pair_touch` on the client's key, at most once per `EdgePairTouchInterval` (5 min) a process. A listener that is revoked, removed or gone is touched by nobody, and its pairs end within 15 minutes whatever any sweep did. A long-lived stream of a live listener keeps its pair with no Find. A `ur/` pair stands for the dialing sidecar's authorization at Find and keeps §9.6's rule: 60 minutes, refreshed per Find, never touched by the listener (question details-13-edge-pair-life).

**The registration path** (SOCK-M5-05), in order, for one page:

```text
1  authenticate: the caller's client, network and sidecar_id (QD-040). No sidecar_id outside urnetwork-edge: denied.
2  the control bound: one token; then the fair queue. unavailable with retry_after_ms
3  the page's shape, whole, before anything is judged: at most 1,024 entries, sorted by name key, each inside
   [key_start, key_end), field sizes as §9.5. A page that fails is refused invalid, and writes nothing.
4  the network's view S (SocketGate.View), taken once for the page. Unloaded or not fresh: unavailable. The
   removed-client set holds the caller: 401.
5  per entry, in memory: the namespace (plaintext only for tls/, smtp/, ur/); the claim under the sidecar's
   identity key in S, verified once per (client, claim bytes, key) and remembered; MayListen for the caller's
   subject; the kill set; the namespace's ValidateListen. Each entry ends allowed or refused.
   ValidateListen undecided: the page is refused unavailable.
6  SocketStore.ApplyPage with the allowed entries, S's position, the page's set_version, the sidecar_id, and
   the name keys of the refused entries. The store, for the page's range: puts the allowed; dels the refused
   with cause 1 at S's position; dels with cause 0 what the client's set holds there and the page lacks.
7  per entry's outcome: ok; taken; revoked (refused and the store removed a lease); denied (refused, none
   held). A stale put writes nothing, and the page's commit then answers §9.5's older-set refusal.
   fenced: gate.Observe(N, the fence's position), and the page's answer is unavailable with a 1 s
   retry_after_ms, its other entries applied. A removal answered kept with a position, or a put whose
   lease already stood at a higher position: Observe likewise, and the entry's own status stands.
8  FirstListen and LastUnlisten for the transitions the store reported. No SocketHint: the caller holds its answer.
9  pairs: if an edge entry was accepted, pair_touch (rate-limited); if the client's set now holds no tls/ or
   smtp/ name key and this call removed one, pair_remove at S's position.
10 answer: statuses, the stored set_version, server_time, ticket keys, the edge network id, and whether the
   network is spent.
```

`ApplyPage` keeps its landed order (the set's begin, the groups, the set's commit, the listing). Its commit script also answers whether the set still holds a key that begins `tls/` or `smtp/`, which step 9 reads.

**The find path** (SOCK-M5-06):

```text
1  authenticate; the control bound (the edge bound for urnetwork-edge callers); the fair queue: unavailable
2  the kill set: denied
3  the view S of the name's network (SocketGate.View). Unloaded or not fresh: unavailable.
   MayDial for the caller (an edge: autogroup:public, and MayPublish on tls/): denied, before any group is read
4  the paying network is spent in the over-limit snapshot: quota
5  the failed tickets: each verified and held by the caller, else dropped
6  SocketStore.Pick: no_listener, busy, or a primary and a backup, each with its m record
7  the newest view S' (View again: one pointer read). If its position is not S's, step 3's verdicts are taken again on
   S', in memory. Then, for each picked listener L, the listener check:
     L's client is in the removed-client set, or its name in the kill set: refused
     on ur/ nothing more: the listener is a platform client the service authorizes (§9.4), with no subject
     L.pv above S'.n: gate.Observe(N, L.pv). A fresher process admitted it at a position this one cannot
       judge, so L gets no ticket here; if no picked listener can be judged the Find answers unavailable
       with a 250 ms retry_after_ms, by when this process has loaded
     otherwise: MayListen for L's subject (its stored sidecar_id) on the name at S', at the time now, and
       on tls/ MayPublish for it: refused if either refuses. A grant that ran out by time since L's last
       heartbeat is refused here too.
   a refused L is removed for cause at S'.n (RemoveEntries, which leaves the tombstone), with its pairs if it
   holds no other edge entry, and a SocketHint. If the primary got no ticket the backup, if it passed, is the
   primary. If every picked listener was refused: one more Pick, then no_listener.
8  for an edge or ur/ Find: pair_set for each listener of the answer, at S'.n. {0, floor}: Observe(N, floor),
   and the Find answers unavailable. A pair this process wrote within PairWriteInterval (60 s) for the same
   listener, listen_id, dialer and expiry is not written again.
9  sign: policy_version S'.n, grant_id and grant expiry from the dial verdict (the publish verdict on tls/)
```

A refusal signs nothing. Nothing is signed for a listener the signer's own state refuses, at the position it holds when it signs.

**The over-limit poll.** One goroutine re-reads `Quota.OverLimit` every 5 s with a 2 s bound and stores the answer behind an atomic pointer; `Spent(networkId)` is one map read of the spent set alone. A failed read keeps the last answer, counts `urnetwork_sockets_over_limit_stale_total` and leaves its age in a gauge. The gate is not ready until one read succeeded.

**Removals.** The host's one key-event subscriber calls these, and each does its work on the engine's own workers:

```text
ProjectionChanged(N)   the {acl_<N>}v event: evidence for N. ProjectionsResync, after a resubscription: the
                       version check above.
ClientRemoved(C)       C joins the removed-client set (kept RemovedClientTtl, 10 min, past any lease) at once.
                       Then SocketStore.RemoveClient: it works through C's set 1,024 name keys at a time,
                       dels each lease with cause 2, takes the batch out of the set, and at the end deletes the
                       set and runs pair_remove at 2^64 - 1. Processes holding the same event share the set's
                       batches and none repeats another's. No SocketHint: C's transports are closing. A child
                       is removed by its own event.
KillChanged(N)         the kill set is read again; Find and registration read it in memory.
the cache's OnLoad     when N's position rose: N is queued for a revocation sweep.
```

*The revocation sweep.* One worker pool a process (`SweepConcurrency`, 4). For a queued network at snapshot S(n): skipped when every entry of the run that raised the position is a statement of a kind that cannot take a socket verdict away: SIGNED_GRANT_ACTIVATE, SIGNED_UNSUSPEND, SIGNED_SIDECAR_ADMIT, SIGNED_MEMBER_ADMIT, SIGNED_ADMISSION_CONFIRM, SIGNED_OWNER_CONFIRM, SIGNED_KEY_REGISTER, and the repo statements no socket check reads (SIGNED_EVS_SHARE and SIGNED_REPO_CREATE through SIGNED_AUDIT_OPT_OUT). Every other statement kind, a BASE, a TICK and any kind the table does not hold sweep. The table is one function, `socketEntryMayNarrow`; the wrapped source sees each run's entry bytes and reads only `AuthEntry.kind` and the body's `Signed.type`. Not before `SweepMinInterval` (10 s) after this process's last sweep of N, always at the newest position. Then `ClaimSweep(N, n, 30 s)`: one script on `{sn_<N>}names` that takes the claim in field 0x00 unless a claim at n or above is unexpired. The claimer pages `{sn_<N>}names` 256 names at a time, renewing its claim at each page, reads each group's listeners, and applies step 7's listener check to each lease whose pv is at most n. It removes the refused in batches with `RemoveEntries` at cause 1 and position n, runs `pair_remove` for a listener left with no edge entry, sends `SOCKET_HINT_REVOKED` to each removed client, and yields between pages.

A sweep that dies leaves nothing wrong: each lease it did not reach is judged at its listener's next heartbeat by whichever process serves it, and at any Find that picks it; its pair ends by `EdgePairTtl`.

**State machines.**

```text
a network at one process
  unloaded --first load--> fresh --evidence--> behind, in grace --a load covers it--> fresh
                                               behind, in grace --5 s--> behind (unavailable) --a load covers it--> fresh
a lease of (group, L)
  none --put--> lease{pv, sv} --put: a heartbeat, or a fresher process--> lease{max pv, sv}
  lease --a page of a newer set lacks it--> tombstone{sv', 0}, 60 s
  lease --refused at x by a page, the sweep or a Find--> tombstone{sv, x}, 10 min
  lease --its client removed--> tombstone{sv, 2^64 - 1}, 10 min
  lease --45 s with no page--> none
  tombstone --put at or above both numbers--> lease        (granted again, or the page retried)
  tombstone --put below either--> tombstone                (fenced)
a pair of (L, dialer)
  none --pair_set at or above the floor--> pair --pair_touch, pair_set--> pair
  pair --pair_remove at x--> floor{x}, 10 min; pair --its ttl--> none
```

**Settings**, added to `SocketsSettings` and `SocketStoreSettings`, each a positive duration or count that `Validate` holds:

```text
GateBehindGrace        5 s      TombstoneTtl           10 min (above the cache's poll and one load)
UnlistenFenceTtl       60 s     RemovedClientTtl       10 min
EdgePairTtl            15 min   EdgePairTouchInterval  5 min     PairWriteInterval  60 s
SweepMinInterval       10 s     SweepClaimTtl          30 s      SweepPageCount 256, SweepConcurrency 4
OverLimitInterval      5 s      OverLimitTimeout       2 s
BehindRetryAfter       250 ms   FencedRetryAfter       1 s
```

**Bounds, stated.** T0 is api's append of the entry that revokes listener L's grant, with its INCR of `{acl_}v`.

```text
a process that gets the event    signs no ticket for L and writes no lease or pair for it after T0 + event
                                 delivery + GateBehindGrace (5 s): by then it has loaded and refuses, or is
                                 unavailable for the network
a process whose event was lost   until its resubscription's check, else the cache's poll: T0 + 5 min 30 s +
                                 its load (30 s at most); sooner at its first store answer that names a
                                 fresher position
tickets already signed           stay good for their 30 s
a lease admitted below x         cannot be written once any process removed L's lease for cause at x (10 min
                                 of tombstone); L's first registration in flight at T0 holds at most its 45 s
a tls/ or smtp/ pair             removed when a fresh process removes L's last edge entry, and not rewritable
                                 below that position; else gone 15 min after L's last accepted registration.
                                 Contracts already issued run to their own deadline (§6.10.1: 60 min at most)
a removed client                 not found by a process once its event arrives; its leases at most 45 s
a spent network                  Find answers quota within the 5 s poll and its 2 s read while api answers; the
                                 edge's own lease is the stop meanwhile (13.2.2)
```

**Wire.** Nothing a client sends or reads changes. A closure upload's 429 carries the same `QuotaRefusal`. `SocketRegistrationsResult` and `SocketFindResult` keep their statuses and codes, `unavailable` with `retry_after_ms` covering the new refusals. Between a host and api, a batch travels with its `UsageCarve` rows, as QUOTA-M2-05 already takes them. What changes is in Redis, as above, and in §2.8's rows for it (13.8).

### 13.3 Invariants and why they hold

**Pacing.**

```text
P1 Rate     every second takes at most R uploads, whatever asks arrive and in whatever order
P2 Cells    for every second from the current one on: its seats, plus what it has taken if it is current, are
            at most R
P3 Turn     an eraser that asks when it was told to takes within (live seats + 2R) cells of its ask, and of each
            take after it; with k erasers asking all the while, exactly every k cells
P4 Ghost    a seat nobody uses costs the cell it names and nothing else
P5 Once     a debit id that passed counts once, and one that was refused may ask again
```

*Why.* P2 is kept by `NextSeat`, the only writer of seats: it puts a seat in second C only when C's count is below R, and when it moves on to C + 1 that second is empty, because the tail is the latest seat and the candidate was past it. A take removes one seat of the current second and adds one to `taken`, so the sum is unchanged. P1 follows: a take needs a due seat, the purge leaves only seats of the current second or later, so every take in second S used a seat of S, and those with `taken` never passed R. P3: an eraser holds one seat at a time, so at most k seats are out; every second between now and the tail's is full, since the tail moves a cell at a time and skips only out of a full second; so a new seat lies at most k - 1 cells of others, R of the current second's takes and R - 1 of a skipped remainder ahead. The seat is honored when its instant comes whatever the others did, because P2 held its cell. P4: an unused seat lapses at its second's end and was one of that second's R. P5 is the script's first lines and the recording rule.

**Leases.** For one balance: `bal` is `balance_byte_count`, `pending` the unapplied journal rows on it.

```text
L1 NoOverdraw   bal - pending >= 0: the debits leases journal against a balance never pass it
L2 BilledOnce   for each process, the bytes journaled for it never pass the bytes it spent
L3 Backed       available <= the amounts of the entry's live tokens: a host never spends bytes Redis gave back
L4 Return       a token nothing will release is gone 15 min after its lease's last extension, a carved one in 24 h
L5 Order        a lease's spent bytes are debited to its balances in draw order and its unspent rest returns in
                reverse (E-a, E-b)
```

*Why.* A reservation grants at most `min(reading, floor) - T`, T being the sum of the balance's tokens. Every byte reserved and not yet debited is in a token: a lease token from its reservation, a carved token from its carve to the flush's commit. So what is free in truth is the balance less the tokens of bytes not yet debited. A reading is the balance at an earlier time, so it is too high by exactly the debits applied since, and those fall in two groups. A debit whose token is still there is subtracted in T. A debit whose token `release-debited` removed lowered the floor, in that same script, to the balance it left, so the floor is at most the balance after the last such debit; and the floor is still set, because it lives `FloorTtl` and no reading older than `MaxCreditAge` is used, so a floor that has expired was set before the reading was taken, and the reading already holds its debit. So what the script grants is free in truth. A byte a host spends was granted (`Spend` only takes `available`, which only reservations add to: L3, with expiry removing bytes before Redis can and `carve` shrinking a draw only by what its plan attributed). A byte is journaled only after its `carve` answered {1, sum}, which happens only while the lease tokens still hold it, and from then the carved token holds it until the flush's commit. So every journaled byte is inside R until its debit is applied, and L1 follows. L2: a batch is planned once and keeps its id; `carved` only rises; api applies an id once; a row is keyed (balance, usage id). L4 is the tokens' lifetimes with no marker. L5 is the attribution rule and the order of `settle` at close.

**Sockets.** n(p) is process p's verified position, which only rises (the cache never installs a lower pin: I-16, section 5).

```text
S1 TicketSound    a ticket is signed only where the signer's position, when it signs, allows the dial and the
                  listener
S2 FencedLease    once a lease of (group, L) was removed for cause at x, no lease of it admitted below x stands
                  while the tombstone lives
S3 SetOrder       once a lease was unlistened by set version u, no lease written by an older page stands
S4 PairFenced     once L's pairs were removed at x, no pair written below x stands while the floor lives
S5 Evidence       no page is judged, no pick made and no ticket signed by a process more than GateBehindGrace
                  after it had evidence that the log passed what it holds
S6 Bounded        the bounds of 13.2.3's table
```

*Why.* S1 is step 7: every verdict a ticket rests on is taken on the snapshot read at step 7, and a listener is passed only if that snapshot allows it then. S2 and S3 are the group script: a `put` below a tombstone's position or set is refused in the same script that would write it, a tombstone is cleared only by a `put` at or above both its numbers, and a lease keeps the highest position it was admitted at. After a tombstone is cleared by a newer admission and that lease is unlistened, an old `put` is still refused, by its set version, which is below the unlisten's. S4 is `pair_set`'s check against `~f`. S5 is the fresh rule, read at a page's step 4 and a Find's step 3, with step 7's listener check refusing a lease admitted above the signer's position; a store call already in flight when the evidence came is what S2 and S4 are for. S6 follows from S5 for a process that has evidence, from the resubscription check and the poll for one that has none, and from the lifetimes.

**The cross-cutting rules, where they bear.**

```text
X3, D-SOCK-14   every verdict is the gate's, on a state it verified (section 5). A lease's pv, a tombstone and a
                floor only refuse writes; no ticket is signed on them, only on the signer's own state
X1              an edge cannot judge a listener, since TLS ends at the listener: step 7's listener check is the
                service's, and is why it exists
X8, D-SOCK-4    the service contacts no listener: a removal is a store write and a hint
X10, I-15       a removed client: the removed-client set at once, RemoveClient's tombstones, its pairs' floor
X11             an edge Find's payer is the listener's network; the edge's lease (13.2.2) is the stop, and
                Find's spent check saves the ticket
C9              the pair is a lease the listener's registration keeps, and its floor outlives its removal
I-4             the service originates only denials here: unavailable, revoked, a removal for cause
I-12            no Postgres on a page, a Find, a Spend, a reservation or a carve; api is reached only off them
I-13            no metric or log line carries a network, name, client or balance id; a tombstone holds only ids
                its group already held
I-16            a process's position never lowers; pv, sv and the floors are compared and never raise a verdict
```

**The models.** Three small models, one per part, each with twins that break one rule and must fail, and a reach configuration that denies a state the design must reach. `Pacing.tla` counts time in cells and lets Wild erasers ask at any time or never; time passes only once every obedient eraser with an ask due has asked. `Lease.tla` has one balance, hosts that read, reserve, spend, plan, carve, post, crash, restart, expire and close, a flush in two steps, lost post answers and late duplicate carves; it holds one live token a lease, each reservation being a token of its own that never grows, and leaves the attribution over several draws and balances to the argument above. `SockReg.tla` has one listener on one name, a log whose entries leave its grant standing or not, two or three processes with their own positions and evidence, and registration and Find in two steps each; its processes act on no grace (GateBehindGrace 0), so S5 there is the strict form.

Working out the lease model changed the design twice. A first version let a host carve a batch planned under one token out of a token it reserved later, and `Backed` failed at depth 10: bytes spent under a token that has since expired are given up, never carved from another. A second version merged a lease's reservations into one token, and a late duplicate carve whose `expect` matched again moved bytes twice: each reservation is its own token, so an amount never returns.

Runs of 2026-11-10, TLC rev d8fb231, one pass of `run-sched.sh details-13 all`, which ended 0: every design configuration passed and every twin and reach configuration ended with its one invariant violated. Each run is breadth-first; a design's states are its whole graph at its bounds, a twin's and a reach configuration's those found when the violation was. Disk is the most the run's state directory held, sampled every 5 s, so 0 for a run that ended inside the first sample. The machine was shared with four build lanes, and the two lease designs took under 7 and 5 minutes when run alone.

```text
configuration              what it holds                                                  result                                           states  depth         time     disk
Pacing                     three obedient erasers and one wild, R = 2, 14 cells           pass                                              6,899     33    under 1 s     0 MB
Pacing-Ghosts              one obedient eraser among three wild, R = 2, 12 cells          pass                                          1,241,261     29         15 s    79 MB
Pacing-Three               three obedient erasers and two wild, R = 3, 12 cells           pass                                            201,974     30          3 s     0 MB
Lease                      two hosts, a balance of 3 and draws of 2, two tokens a host    pass                                         37,710,290     38  11 min 08 s   970 MB
Lease-Crash                two hosts, a balance of 2 and draws of 2, three tokens a host  pass                                         44,646,597     41  11 min 21 s  1219 MB
SockReg                    two processes, a log of two entries, three pages               pass                                          1,042,443     20          3 s     0 MB
SockReg-Regrant            two processes, a log of three entries, two pages               pass                                          1,321,149     23          3 s     0 MB
SockReg-Wide               three processes, a log of two entries, three pages             pass                                         17,808,184     22   1 min 29 s   557 MB
PacingTwin-Arrival         the landed bucket, every eraser obedient                       Turn violated, a trace of 135 states          7,488,412    135         14 s    81 MB
PacingTwin-Tail            a bucket refusal goes to the tail; two late erasers            Turn violated, a trace of 68 states           1,804,133     68          5 s    82 MB
LeaseTwin-NoFloor          a reservation trusts the host's reading                        NoOverdraw violated, a trace of 17 states       614,374     18          2 s     0 MB
LeaseTwin-FloorExpires     the floor forgotten under an older reading                     NoOverdraw violated, a trace of 17 states     1,240,976     19          3 s     0 MB
LeaseTwin-ReleaseFirst     the flush releases before it commits                           NoOverdraw violated, a trace of 15 states       252,787     17          1 s     0 MB
LeaseTwin-BlindCarve       a carve that moves whatever its token holds                    NoOverdraw violated, a trace of 24 states    11,872,096     24         42 s   872 MB
LeaseTwin-SpendPastExpiry  a host spending past its token                                 Backed violated, a trace of 4 states                 85      7    under 1 s     0 MB
LeaseTwin-Replan           an unanswered batch planned again                              BilledOnce violated, a trace of 10 states         1,998     10    under 1 s     0 MB
SockRegTwin-NoTombstone    a removal that leaves nothing                                  FencedLease violated, a trace of 9 states        27,786      9    under 1 s     0 MB
SockRegTwin-NoRecheck      Find signs for what the pick returned                          TicketSound violated, a trace of 7 states        11,559      8    under 1 s     0 MB
SockRegTwin-NoPairFloor    a pair written at any position                                 PairFenced violated, a trace of 9 states         32,004     10    under 1 s     0 MB
SockRegTwin-BehindAllows   a process that admits while behind                             EvidenceBound violated, a trace of 5 states         151      5    under 1 s     0 MB
SockRegTwin-NoSetVersion   pages taken in any order                                       SetOrder violated, a trace of 9 states           24,251      9    under 1 s     0 MB
LeaseReach-Settled         a balance spent by two hosts and debited to the byte           NotSettled violated, a trace of 18 states       894,089     19          3 s     0 MB
SockRegReach-Regrant       revoked, swept, granted again, found again                     NoRegrant violated, a trace of 12 states        319,172     13    under 1 s     0 MB
```

What the models do not show: liveness beyond the reach configurations (a lease that is never starved of renewals, a sweep that ends); the attribution of spent bytes over several draws; clocks, which appear only as the order of steps (the floor's lifetime against a reading's age is `LeaseTwin-FloorExpires`'s assumption, and a seat's tolerance is not modelled); and Redis loss, which empties each model's store and is 13.5's subject.

### 13.4 Cost

**Pacing.** One script a `CountRate` call, as today. Inside it the pacing step is a range delete, a score read and at most two range counts on the turns set, O(log k) each, plus a hash read and write; the landed step is the same order. The turns set holds one member an eraser with a live seat, about 100 B each: 0.5 MB for a Team's 5,000 erasers all asking, under the keys' 48 h ttl. No new key.

```text
k erasers asking     1        4        12       100      5,000
one round, k/R       0.25 s   1 s      3 s      25 s     20 min 50 s   (69 turns a day, above the allowance's 60)
a missed second      costs nothing while the second has a free cell; in a full network, one more round
tolerance            from the seat's instant to its second's end: 1 s, 750, 500 or 250 ms by cell
```

**Leases.**

```text
Spend                      one compare-and-swap, one add, one load for the renew mark; no lock, no I/O, 0 allocs
open                       one balance read unless one under 5 s old is held; one script a balance drawn (usually 1)
renewal                    one script a balance drawn; a slow lease, one per 48 MiB spent; a fast one, about one
                           per 4 s (a draw of 4 s of its traffic, renewed with 2 s left)
extend                     one script a live draw per 5 min: 10,000 live leases cost about 40 calls a second
carve                      one script per (lease, balance) with spend in a window: 10,000 busy leases, 167 a second
post                       as today: one batch a producer a minute, now with at most 4,000 carve rows
flush                      the same scripts, release-debited for release; one RETURNING on each debit
close                      one script a draw
Redis                      about 200 B a live draw (a hash field and an expiry member), the same per carved row
                           for the minute until its flush, and 60 B a balance for the floor
held unspent               at most max(64 MiB, 4 s of its rate) a lease: ten edge hosts on a Community network
                           hold 160 MiB of its 30 GiB day, 0.5%
at 1,000 Mbit/s            a draw of 512 MiB (4 s of 119 MiB/s, rounded up to 64 MiB), renewed with 238 MiB left:
                           2 s for one script, where a fixed 64 MiB leaves 134 ms
a kill                     unbilled: the open window, 60 s of that process's lease bytes at most; held: its lease
                           tokens for 15 min, and a window's carved bytes for 24 h if it died between carve and post
Redis lost                 the tokens are gone and live leases keep what they hold: over-admission at most the
                           draws held, as §20.15 says, and ended at each lease's next extend (5 min)
```

No Postgres on any path a host runs. `Spend` is §22.5's T1 row.

**Sockets.**

```text
a registration page    the landed calls: no script is added. The three record fields ride the put, and the
                       tombstone the del. One pair_touch a client with edge names per 5 min a process.
                       CPU: one Ed25519 verify a claim the process has not seen (about 50 µs, so a first page
                       of 1,024 names is 50 ms and a heartbeat none), and under 1 µs an entry for the gate
100,000 listeners      about 6,700 calls a second, as §9.8
a Find                 one script, as §22.5 counts it. In memory: the dial verdict and one listener check a
                       picked listener, under 1 µs each. An edge Find adds a pair_set a listener only when this
                       process has not written that pair in the last 60 s
the gate               one GET of {acl_}v a load; after a resubscription one GET a loaded network, 1,000 a
                       pipeline: under a second for 100,000 networks, against reloading them all
a sweep                one claim script, one listing page per 256 names, one read script a group, one del a
                       refused lease. 1,000 names: about 1,000 reads, 100 ms pipelined. At most one per 10 s a
                       network a process, one process a position, none for a run of widening entries
memory                 a tombstone or a floor is one hash field of about 60 B for 10 min; the removed-client
                       set 16 B a removal for 10 min
the over-limit poll    one call per 5 s a process
```

§22.8's Find budget (p99 at most 50 ms at the service) and §9.8's registration rate are unchanged.

### 13.5 Failure modes and recovery

```text
pacing
Redis lost                     seats and counts are gone: the next asks are seated afresh and the second's count
                               starts at 0, so up to R more may take in the second of the loss; §20.7's one
                               window of fail-open, as today
a caller's clock ahead         the network's clock follows the highest; seats lapse early by the skew and their
                               holders are seated again. Behind: the caller is treated as arriving at the clock
an eraser that never returns   its seat's one cell goes unused
an upload refused for its      asks again under the same debit id and is judged afresh; one that passed and lost
turn, or whose answer is lost  its answer replays as passed, with no second turn

leases
host killed                    its open window's bytes are unbilled; its lease tokens return in 15 min; a batch
                               carved and not posted leaves its carved tokens for 24 h. Nothing is billed twice
reserve unanswered             repeated under the same token name: the script answers the token it wrote. After
                               3 tries the name is abandoned and its token lapses
carve unanswered               repeated with the same arguments: case 1 or case 3 of the script, never a second
                               move. A stray copy arriving later moves nothing
post unanswered                retried under the batch id for 10 min; api applies it once. Dropped at the horizon,
                               counted and alerted: unbilled if it never applied, and its carved tokens lapse
Redis unreachable from a host  no renewal: Spend answers false when the draws run out, the edge resets, and the
                               network is not marked spent. Draws stop being spendable 30 s before their tokens
                               can lapse; bytes spent and not carved by then are unbilled and counted
Redis lost                     tokens and floors are gone. A live host's next extend answers 0 and it drops the
                               draw. Until then it may spend what it held: bounded by the draws. Carves of that
                               time answer {0, 0}: unbilled, never debited unreserved
api or Postgres down           balances cannot be read: a held answer serves for 30 s, then renewals stop and
                               leases run dry. Posts retry and then drop (§20.6's loss row)
flush behind                   carved tokens hold their bytes until it runs: the balance reads lower than it is,
                               the safe side. Past 24 h a carved token lapses before its debit and the bytes could
                               be granted twice: QUOTA-M2-15 adds the flush's oldest-row age as a gauge, to alert
                               at 10 min
a network marked spent while   another host's leases hold the remainder. The 60 s pass clears the mark when
Postgres shows room            Postgres shows room, and the next refused lease sets it again: it can flap at
                               that period until the others close or spend (quota-m2-03-readings #10)

sockets
key event lost                 nothing is evidence, so the process serves what it holds until the resubscription
                               check, a store answer naming a newer position, or the cache's poll
source down, log still         no evidence, no change: the process serves. This is every api outage
source down, log moved         evidence it cannot follow: after 5 s the network answers unavailable at this
                               process, and clients retry at another
a load refused with an alarm   as above: unavailable for that network here until a load verifies
the store unanswered           the call answers unavailable; a page is idempotent and the next heals it
Redis lost                     leases, tombstones, floors, pairs and the client sets are gone. One heartbeat
                               interval rebuilds the leases (§9.5). A lease a stale process writes meanwhile has
                               no tombstone to stop it: S5 and S1 still hold, and the bound is the stale process's
the sweep's claimer dies       the claim lapses in 30 s; each lease it missed is judged at its next heartbeat or
                               pick; pairs end by their 15 min
over-limit read fails          the last answer serves, its age is a gauge, and the edge's lease is the stop
a client removed mid-page      its puts may land after RemoveClient's dels and are refused by the cause-2
                               tombstones where it held a lease; a name it never held keeps a lease 45 s, which
                               every process holding the event refuses to hand out
```

### 13.6 The test plan

**Unit tests, sidecar.**

```text
host_quota_keys_test.go        QuotaClosurePacing: a seat in a second with a free cell; a seat pushed out of a
                               full second to the next one's start; a seat lapsing with its second; an eraser
                               with a lapsed seat seated in the current second when it has a cell and at the tail
                               when it has none; the clock never running back under two callers; R not dividing
                               10^6 (R = 3, 7) keeping P1 and P2 over a random run from a fixed seed
sidecartest/fake_quota_test.go the fake on the same vectors as the script; a refused debit id judged afresh, a
                               passed one replayed with no second seat; no seat for an ask its allowance refuses
quotasuite                     the pacing cases rewritten to the seat rule: equal turns (as written); a waiting
                               eraser keeps its place (as written); returning together: twelve with lapsed seats
                               ask at one instant in a hostile fixed order, R uploads are taken that second (two
                               by the first asker, whose next seat is the cell behind its own), each of the
                               rest is told an instant in a later second, and all twelve have taken three
                               times within 10 s; a replay of a refusal after its retry_after_ms passes
socketsservice/                registrations_test.go, find_test.go, gate_projection_test.go, sweep_test.go,
                               over_limit_test.go: 13.7's lists, on FakeSocketStore, a fake gate source and
                               the fake clock
sidecartest/socket_store_suite RunSocketStoreSuite gains: put below a tombstone's position fenced, and the fence's
                               position returned; put at or above it clears it; put of an older set_version
                               stale; an unlisten older than the lease kept; a cause-1 del of a lease admitted
                               above its position kept; tombstone ttls on the injected clock; the group's hash
                               surviving its last listener while a tombstone lives; pair_set below the floor
                               refused; pair_remove keeping the floor; pair_touch never lengthening past a
                               grant's expiry; ClaimSweep won once per position
```

**Unit tests, server.**

```text
model/quota_rate_pacing_test.go        the three landed tests on the new script, the stampede with a fixed
                                       hostile order and no shuffle; script against QuotaClosurePacing on fixed
                                       vectors; the debit record written only on a pass
model/quota_lease_reservation_test.go  carve: moves once; a replay finds the destination; a copy after the
                                       destination's release moves nothing; a source short of expect moves nothing
                                       and writes nothing; total unchanged. extend: answers the amount, 0 when gone.
                                       The floor: a stale high reading clamped after release-debited; an expired
                                       floor set again; six-key callers unchanged, by a golden run of the
                                       contract tests. redisGrantProbeScript's prelude cut still found
model/service_debit_flush_test.go,     release-debited carries the balance the debit left; the kill points as
model/subscription_transfer_debit      landed; a lease-meter event whose carves fall short of its bytes refused
quotahost/lease_test.go                Spend under the race detector with 0 allocs and no host call (§22.5's T1
                                       row, under DenyPostgresForTest and an op-counting Redis); attribution by
                                       rank across draws made out of order; renewal at the mark, and at 4 s of a
                                       fast rate; a reservation unanswered three times abandoned; expiry on the
                                       fake clock dropping a draw 30 s before its token's end and counting its
                                       uncarved bytes unbilled; close settling the highest rank first; a carve
                                       answered {0, 0} dropping its part; a batch's plan reused across its retries
model/socket_store_test.go             RunSocketStoreSuite on Redis with the new cases; the CROSSSLOT check over
                                       the changed scripts
```

**Schedule rows.** FS-44 gains, on T2 and T3: a host killed between a carve and its post (no debit, the carved token gone at 24 h on the fake clock); a carve whose answer is lost, retried, with a third copy delivered after the flush (one debit, the lease token moved once). FS-46's lease clause reads the lease token gone 15 min after the kill and the line's reservation with it. FS-47's pacing clause runs the stampede in a fixed hostile order. A new row for §22.5's §20 line, FS-44's twin for balances: two hosts on one balance, one holding a 30 s old reading, the other's debit flushed between: the second reservation is clamped by the floor and the balance ends at zero, never below. §22.5's §9 row gains: a put stalled at a barrier across a revocation and its sweep is fenced and answers unavailable, then revoked; a Find that picked before the sweep signs nothing and writes no pair; a process whose event is withheld serves until its resubscription check and then stops within the grace; a process whose source fails after evidence answers unavailable for that network alone. §22.7's revocation suite ("X's sockets ... end") reads the bounds of 13.2.3's table.

**Model twins in Go.** Each twin's rule has a test that fails when the rule is removed, named for it: `TestPacingAdmitsBySeatNotArrival` and `TestPacingBucketRefusalKeepsThePlace` (Arrival, Tail); `TestLeaseReservationClampedByFloor`, `TestLeaseFloorOutlivesAReading`, `TestFlushReleasesAfterItsCommit`, `TestCarveMovesOnce`, `TestLeaseStopsSpendingBeforeExpiry`, `TestBatchPlanKeepsItsId`; `TestRemovalLeavesATombstone`, `TestFindJudgesTheListener`, `TestPairWriteBelowFloorRefused`, `TestBehindProcessAdmitsNothing`, `TestOlderPageIsStale`.

### 13.7 Implementation notes, task by task

Order: QUOTA-M2-14 and QUOTA-M2-15 at once, in the ops lane; QUOTA-M2-07 after QUOTA-M2-15. SOCK-M5-18 at once, in the edge lane; then SOCK-M5-05 and SOCK-M5-06 in either order; SOCK-M5-07 beside them, since it lands against the fake source, and last for its end-to-end tests.

**QUOTA-M2-14, closure pacing by seat** (new; sidecar and server; S). This is the task that carries the pacing change, on QUOTA-M2-01's and QUOTA-M2-03's landed code, before QUOTA-M2-13's FS-47 clauses and before any caller beyond the upload route exists. `sidecar/host_quota_keys.go`: `QuotaClosurePacing` keeps its fields and gains `clock`; `Ask(eraserId, now, perS)` and `Take(eraserId, now, perS)` lose the horizon; `nextSlot` becomes 13.2.1's `NextSeat`; `quotaClosurePacingSpacing` rounds up. `sidecartest/fake_quota.go`: the pacing step runs only when no counter refused, a refusal is not recorded under its debit id, `ClosureSlotHorizon` leaves `FakeQuotaSettings`. `sidecartest/quotasuite`: `caseAReplayAnswersItsFirstResult` becomes the pass-only rule, `caseErasersReturningTogether` the seat rule. `server/model/quota_rate_script.go`: the paced block as 13.2.1, after the counters' loop and only when `refusal` is false; the record written only at the end; `ARGV[6]` (the horizon) dropped and `QuotaRateSettings.ClosureSlotHorizon` with it. `evsservice/upload_segment.go` needs no change: its debit id is right under the new rule. The landed `TestClosurePacingServesKErasersEveryKOverR` and `TestClosurePacingObedientEraserKeepsItsPlace` are kept as written; the stampede test loses its shuffle.

**QUOTA-M2-15, the reservation script's lease operations** (new; server; M). `server/model/subscription_redis_admission.go`: the seventh key, the floor rule on the reserving operations when it is passed, `extend`, `carve` and `release-debited`, all below `local rawTotal=`. `redisContractReservationKeys` keeps six; a new `redisLeaseReservationKeys` returns seven. `server/model/quota_lease_reservation.go`: the Go callers, each taking a `QuotaRateRedis`-shaped runner so a host passes its `ServiceHost.Redis`. `server/model/service_debit_flush.go` and `subscription_transfer_debit.go`: `RETURNING balance_byte_count` and `release-debited` with seven keys; the service flush also exports its oldest unreleased row's age, `urnetwork_service_debit_oldest_seconds`, as the transfer flush does. `server/model/service_usage_batch_model.go`: a lease meter's event must equal its carves. Trap: the contract admission path is not touched, so M6's escrow benchmark reads the same admission; the transfer flush's release gains one SET in the script, which the benchmark's settlement half should be rerun on.

**QUOTA-M2-07, leases** (held; L; scope changed). It loses the script's operations to QUOTA-M2-15 and keeps the host: `server/quotahost/lease.go` (the set, entries, `Spend`, draws, renewal, expiry, close), `lease_balances.go` (`BalanceSource`, the 5 s and 30 s ages) and the `ReportUsage` wrapper's plan, carve and post. It gains the repo sidecar: `sidecartest/fake_quota.go` takes the same rules where a test can see them (a lease token's 15 min against a carved one's 24 h, expiry's unbilled bytes, no debit at apply for a lease meter), and quotasuite's lease cases stay as they are, which the real lease must pass at their slow rate. Build order: the entry and `Spend` with their T1 test; draws on QUOTA-M2-15's `reserve`; attribution and the plan; the carve and post; expiry and extend; close and drain; renewal's rate rule last. Traps beyond the plan's: a draw's bytes join `available` only when its answer arrives; the plan is made once per batch id, and a carve's `expect` is fixed when it is first sent; one operation a token at a time; a carved token is never released by the host; `MarkSpent` is called only when Redis answered and reserved nothing.

**SOCK-M5-18, store fences** (new; sidecar and server; M). SOCK-M5-03's contract and SOCK-M5-04's scripts, both landed. `socketsservice/store.go`: `SocketStorePage` gains `PolicyVersion`, `SidecarId` and `RefusedNameKeys`; `SocketStoreEntryOutcome` gains `Fenced`, `FencePolicyVersion`, `Stale` and `PriorPolicyVersion`; `SocketStoreListener` gains `SidecarId`, `PolicyVersion` and `SetVersion`; `SocketStorePageResult` gains `EdgeEntriesRemain`; `RemoveEntries` takes a cause and a position and answers each ref removed, kept (with the lease's position) or absent; `SetServicePair` takes a position and answers whether it wrote and the floor; `RemoveServicePairs` takes a position; `RemoveClient` works in batches of 1,024 name keys, taking each out of the set once its leases are gone; `TouchServicePairs` and `ClaimSweep` are new. `sidecartest/socket_store_fake.go` and `socket_store_suite.go` follow. `server/model/socket_store_scripts.go`: `m`'s three fields (an `m` without them reads as sidecar empty, pv 0, sv 0, so a lease written before the change is judged at the next Find and replaced at the next heartbeat), `x:<L>`, the group's hash kept while a tombstone lives, the three pair scripts, the claim script on the listing's field 0x00 (which `ListNames` skips), and the commit script's edge answer. Everything else of both tasks stands.

**SOCK-M5-05, the registration path** (held; L; scope as planned, built to 13.2.3's ten steps). Beyond the plan: the snapshot is taken once a page; the claim memo; refused entries reach the store as `RefusedNameKeys`; `fenced` and `kept` answers call `gate.Observe`; step 9's pairs. `GET /socket/list` and `GET /socket/keys` as planned.

**SOCK-M5-06, the find path** (held; L; scope grown by the listener check). Beyond the plan: step 7's second snapshot read and the listener check, with its removal for cause; `pair_set` before signing, with its memo; `unavailable` when no picked listener can be judged. The plan's "one script per Find" test stands for a Find whose listeners pass; its op-counting test names the refused-listener path's extra calls.

**SOCK-M5-07, the gate, the poll and the sweep** (held; L; scope grown by evidence). `gate_projection.go`: the wrapped source, evidence, `View`, `Observe`, `ErrSocketGateBehind`, the resubscription check; `socketsservice/gate.go` gains `SocketGateView`, `View` and `Observe` on `SocketGate` and the error, and `ClosedSocketGate` and `service_test.go`'s gate take them. `over_limit.go` as planned. `sweep.go`: the removed-client set, `ClientRemoved`, `socketEntryMayNarrow` and the sweep. SOCK-M5-08's host calls no `AclGateCache.Watch`. Nothing in `acl_gate.go` changes.

### 13.8 Proposed DESIGN.md text

**§20.7, the closure row.** For "and within its turn of the network's pacing, which takes at most R uploads a second however many erasers ask at once ... each takes one at most every k/R s": "and within its turn of the network's pacing, R being evs_closure_uploads_per_s (4): each asking eraser holds a seat, a cell 1/R s wide at the tail of the network's seats, good from its instant to the end of its second; a seat is handed out only in a second with a free cell, so the network takes at most R uploads a second whatever asks arrive and in whatever order; with k erasers asking, each takes one every k/R s; an eraser that misses its seat's second is seated again, at once while the second has a free cell and else one round later". The wait row keeps its numbers.

**§20.7, Counters.** After "one all-or-none Lua script per `{sq_<network_id>}` and `debit_id`": "a debit id that passed answers pass again and counts nothing; one that was refused is judged afresh".

**§20.14, the `{sq_}` row.** For "last closure ask and next turn, which give k": "each asking eraser's seat, the tail, the second's count and the network's clock".

**§20.6, Leases.** After the diagram: "A lease's tokens are `lease/<lease_id>/<n>`, one a reservation, living 15 min and extended while the lease lives; a carved debit's is `svc/<usage_id>`, living 24 h until its flush releases it (QD-087). A reservation is granted against the lower of the caller's reading of the balance and the balance's floor in Redis, the lowest credit shown in the last 2 min, which each flush lowers to the balance its debit left in the script that releases the debit's token; a host uses a reading for at most 30 s. A carve names what each lease token held and moves only then, so it runs once. A batch is posted only once its carves answered; bytes whose reservation was gone are not billed. A draw is 64 MiB (16 MiB on Community), or 4 s of the lease's rate when that is more, at most 16 draws' worth, renewed at 75% used or with 2 s of traffic left." The loss row's "returns within its 24 h lease" becomes "returns within 15 min, a carved window within 24 h".

**§20.9, E-d.** "or returns within its lease: 15 min for a lease's own tokens, 24 h for carved ones".

**§9.5, Re-check.** Add: "The service stamps a lease with the authorization log position it was admitted at and the page's set_version. A removal for cause leaves a tombstone in the group for 10 min, and an unlisten one for 60 s: a later write admitted below the tombstone's position, or from an older set, is refused."

**§9.6, Find.** Step 4 becomes "pick (9.7), then the listener check: the service signs only for a listener its own newest state allows, removing one it refuses", and step 5 gains "a pair is written only at or above the floor a removal left". The Edge Finds paragraph: "its TTL the lesser of the grant's remaining life and 15 min for `tls/` and `smtp/`, renewed by the listener's accepted registration, and 60 min for `ur/`, refreshed per Find".

**§9.8.** For "on `{X}c_removed` ... a projection revocation or a §21 suspension, deletes entries and pairs and sends `SocketHint`": "on `{X}c_removed` every process refuses the client's leases from memory at once and removes them with its pairs; after an entry that can narrow, one process a network and position sweeps the network's leases against its state, removes for cause those it refuses, with the pairs of a listener left with no edge entry, and sends `SocketHint`; a §21 suspension is refused from the kill set in memory". Add the freshness rule: "A process acts on a network's state only while it has no evidence older than 5 s that the log passed it; past that it answers unavailable for that network."

**§8.9, Gates.** After "and refuse a lower n, or a second A_n at one n, with an alarm": "A sockets process that learns a network's log moved (the `{acl_}v` event, or a position in its own store above the one it holds) and has not verified the new entries within 5 s refuses for that network until it has (§9.8); with no such evidence the last verified state serves."

**§2.8.** sock-1's `sees` gains "the listener's sidecar_id, the authorization log position and set_version its lease was admitted at, and for 10 min after a removal the listener's client_id with the position it was removed at"; sock-3's gains "the position its pairs were last removed at" and its ttl becomes "the grant's expiry, at most 15 min past the listener's last accepted registration (`ur/`: 60 min, refreshed per Find)"; sock-4's `sees` gains "the authorization log position of the network's newest revocation sweep"; api-13's gains "a balance's lowest credit shown in the last 2 min (`{escrow_<balance_id>}approx_floor`)" and, for "64 MiB reservations, 16 MiB on Community", "reservations of 64 MiB to 1 GiB, 16 to 256 MiB on Community".

**§22.** FS-44, FS-46, FS-47 and the §9 and §20 lines of §22.5 as 13.6 words them.

### 13.9 Owner questions

Each is filed under `.stack/questions/`, and the design above is built on its recommendation.

**Seats for closure pacing (`details-13-pacing-seats.md`; answers quota-m2-03-pacing-boundary-order and quota-m2-01-rate-key-grammar #3).** Options: (1) keep reading 19 as built: four erasers that ask first take every turn; (2) the question's option 2, a bucket refusal sends the eraser to the tail: an eraser arriving late at each second's start starves the ones on time; (3) the question's option 3, a rank-ordered `retry_after_ms`: obedient erasers leave in order, but admission is still by arrival, and a winner's next slot is still inside the second it won; (4) seats that lapse with their second, handed out only where a cell is free: admission by seat alone, at the price that a seat missed by more than its second's remainder is lost, which costs a round only in a full network, and that reading 19's 5-minute horizon goes. Recommended: 4, with refusals not recorded under their debit id. It takes none of the question's three as written: option 3's aim by another mechanism.

**What a lapsed reservation's bytes become (`details-13-lease-lapse.md`).** A host cut off from Redis for 15 minutes, or a Redis that lost its state, leaves bytes spent with no reservation to carve. Options: (1) bill them at apply in draw order, as evs's bytes are and as the landed fake does for a lease's excess: nothing is lost, and the debit can land on bytes another host reserved, overdrawing the balance; (2) do not bill them, count them, and alert: under-billing bounded by one window a host, never an overdraft. With it: a lease's own tokens live 15 min, not 24 h, so a dead edge's hold returns in 15 min. Recommended: 2.

**A lease's draw size (`details-13-lease-draw-size.md`).** Options: (1) 64 MiB always: at 1,000 Mbit/s the renewal has 134 ms, and a miss resets the stream; (2) 4 s of the lease's own rate when that is more than 64 MiB, at most 1 GiB: the renewal has 2 s, and Redis loss can over-admit up to the draw; (3) 64 MiB draws issued ahead by time: the same hold in sixteen tokens. Recommended: 2.

**A gate that knows it is behind (`details-13-gate-behind.md`; narrows QD-055).** Options: (1) QD-055 as written: the last verified state serves for as long as the source fails, so a revoked `tls/` listener keeps its visitors at a process cut off from api while the log moves; (2) refuse for a network 5 s after evidence the log moved that the process cannot follow, and serve without limit while there is none; (3) refuse on age alone, after one missed poll: every api outage then stops every Find within 6 minutes. Recommended: 2. It costs nothing while api is down, since nothing moves the log then.

**An edge pair's life (`details-13-edge-pair-life.md`).** Options: (1) §9.6 as written, the grant's expiry up to 24 h, deleted on revocation: a pair a sweep misses, or a Find rewrites, authorizes contracts for a revoked listener for up to a day; (2) 15 min past the listener's last accepted registration, with a floor against rewrites: a revoked or dead listener's pairs end on their own, and a live one's are renewed by its heartbeat; (3) a contract-gate check of the listener's grant at CreateContract: exact, at the price of a gate read on the contract path for platform clients, which §8.10 exempts. Recommended: 2.

**The §2.8 rows (`details-13-metadata-rows.md`).** The store's new values need rows before they ship (I-18): sock-1's sidecar id, position, set version and tombstones, sock-3's floor and ttl, sock-4's sweep claim, api-13's floor and draw sizes, as 13.8 words them. Options: (1) amend the rows; (2) keep the listener's subject out of Redis and resolve it per Find from api, a call on the Find path. Recommended: 1; the sidecar id is what sock-1's stored claim already identifies.

Questions this section builds on, with the option taken: plan-QUOTA-lease-debits (QD-087, carve), plan-QUOTA-host-reach and plan-SOCK-gate-data (QD-055, api's internal surface; narrowed as above), plan-SOCK-client-auth (QD-040, the `sidecar_id` claim, which is the listener's stored subject), plan-QUOTA-small-readings #16 and #19 (ref-counted handles; reading 19's shape, changed as above), sock-pure-est-reach (QD-109, untouched), quota-m2-03-readings #10 (the spent mark's flap, unchanged).
