# TLC runs of the models here

Each run's verdict line as its run script printed it, with the TLC that ran it and the commit it ran
at. modelled.yml records a model's passing gate runs (model, mutants, live) at the digest of its
sources, which a gate lets stand while nothing it modelled changes; this file keeps the verdict lines
behind those records, and those of runs no gate reruns, such as run-tlc.sh's design grounds. Every run
here used the owner's TLC through `ROOT/.stack/tools/tlc`: tla2tools.jar built from master at d8fb231,
which its banner names as `rev: d8fb231`.

## StoreSettle.tla

§19.6's settle rules (D-OPS-20) as QD-744 and DESIGN-DETAILS.md 2.6 give them: rule (2) applies a
drive commit only while its drive still holds the version and the stamp its coordinator read there, a
heal's commit is checked at its drive like any other, and rule (3) holds a failed DELETE's key until
none of its commits may still hold it, so nothing of it lands or is reverted after its release. The
spec and cfg are those 73957fcb landed, and the grounds' rows those of ef621299, which split `sum` into
`sum-heal` and `sum-cancel`. Every run was on 2026-11-14, on a host five build lanes were loading at a
load average between 40 and 90 on 14 cores, so a time here is several times an idle host's. A
breadth-first run on several workers may count a few states more or fewer from one run to the next,
and a twin's count is what TLC had explored when it met its violation.

### The gate's runs

`run-tlc.sh model`, `twins` and `live` for StoreSettle, as model_test.go runs them at a gate, at
ef621299 on 8 workers. modelled.yml records them, beside the same runs at 2ab8fd68, whose run-tlc.sh
had `sum` whole.

```text
== PASS model: exit 0, 19774204 distinct states, depth 30, 13min 23s
== PASS twin-ReleaseOnCancel: NoStaleQuorum violated as it must, exit 12, 5496 distinct states, depth 7, a trace of 7 states, 00s
== PASS twin-NoDeadlineCheck: LateWritesNeverRead violated as it must, exit 12, 567 distinct states, depth 7, a trace of 6 states, 00s
== PASS twin-NoVersionCheck: NoStaleQuorum violated as it must, exit 12, 493614 distinct states, depth 21, a trace of 21 states, 10s
== PASS twin-RevertBelowQuorumOnly: LateWritesNeverRead violated as it must, exit 12, 1281 distinct states, depth 7, a trace of 6 states, 00s
== PASS twin-SettlerRevertsUnseen: NoStaleQuorum violated as it must, exit 12, 880024 distinct states, depth 14, a trace of 14 states, 11s
== PASS twin-HealMinority: NoStaleQuorum violated as it must, exit 12, 10142 distinct states, depth 10, a trace of 9 states, 01s
== PASS twin-NoDriveLock: NoStaleQuorum violated as it must, exit 12, 381078 distinct states, depth 16, a trace of 16 states, 07s
== PASS twin-NoStamp: NoStaleQuorum violated as it must, exit 12, 200574 distinct states, depth 21, a trace of 21 states, 04s
== PASS twin-DeleteReleasesEarly: NoStaleQuorum violated as it must, exit 12, 208954 distinct states, depth 12, a trace of 12 states, 03s
== PASS twin-DeleteReleasesEarly-Settled: FailedDeleteSettled violated as it must, exit 12, 412 distinct states, depth 6, a trace of 5 states, 00s
== PASS live-deletes: exit 0, 263990 distinct states, depth 29, 58s
== PASS live-hosts: exit 0, 66824 distinct states, depth 19, 09s
```

### The design grounds

`run-tlc.sh ground StoreSettle <ground>` for each row `run-tlc.sh list-grounds StoreSettle` prints. A
simulation draws its Traces on each worker, so the states it generates grow with its workers, and it
repeats exactly only on one worker. The liveness rows, `live-deletes` and `live-hosts`, are the gate's
live runs above. On 6 workers:

```text
== PASS ground-sum-early: NoStaleQuorum violated as it must, exit 12, 2239552 distinct states, depth 12, a trace of 12 states, 28s
== PASS ground-revert: exit 0, simulation, 18000002 states generated, 01min 43s
== PASS ground-revert-early: NoStaleQuorum violated as it must, exit 12, simulation, 606896 states generated, a trace of 32 states, 04s
== PASS ground-three-deletes: exit 0, 14569535 distinct states, depth 38, 11min 40s
== PASS ground-three-puts: exit 0, 51072347 distinct states, depth 41, 01h 07min
```

On 8 workers:

```text
== PASS ground-sum-heal: exit 0, 55596704 distinct states, depth 35, 26min 43s
== PASS ground-sum-cancel: exit 0, 78837972 distinct states, depth 31, 31min 22s
```

On 10 workers:

```text
== PASS ground-three-faults: exit 0, simulation, 35000002 states generated, 15min 34s
== PASS ground-six: exit 0, simulation, 35000002 states generated, 19min 07s
== PASS ground-six-three: exit 0, simulation, 35000002 states generated, 23min 11s
== PASS ground-eight: exit 0, simulation, 45000002 states generated, 21min 52s
== PASS ground-wide: exit 0, simulation, 60000002 states generated, 36min 05s
```

The question's first run, at the cfg's bounds with heal and cancels both on, does not finish in the
12 GB a TLC run may keep on this shared disk. Run as a ground on 10 workers, it was stopped twice with
no invariant violated: first by a SIGTERM from outside it at 166,438,178 distinct states and depth 22,
with 22.6 M states still queued, most likely by the orchestrator's tlc-guard, which stops one run whose
state directory passes 12 GB and then exits, as it had by then; then by a watchdog of the same limits
for that run alone, at 12 GB with 80 GB free, at 138,337,131 distinct states. So the grounds run heal
and cancels apart, `sum-heal` and `sum-cancel`, as details/Settle.tla's configurations do, and both
together by simulation in `three-faults`. The two stopped runs ended:

```text
== FAIL ground-sum: exit 143, 166,438,178 distinct states, depth ?, ?
== FAIL ground-sum: exit 143, 138,337,131 distinct states, depth ?, ?
```

### What the runs show

- **The question's two traces** (evs-models-settle-stalled-deletes, which QD-744 answered). Its first
  run was breadth-first at DriveCount=4, Writes={w1,w2} and HostFailures=1 over the cfg it ran on then,
  so with 2 coordinators, a crash, heal and cancels. Those bounds pass in three parts: with heal and
  cancels held still (the cfg itself), with heal (`sum-heal`) and with cancels (`sum-cancel`); with
  both on they did not finish, as above, and are sampled by `three-faults`. At the full bounds twin
  DeleteReleasesEarly (`sum-early`) is refused in the question's own 12 states: two failed DELETEs'
  stalled commits land on drives 1 and 2 after each key's release, and host 2 going down leaves a read
  quorum of drives answering not found. `revert` is its second run, by simulation at §22.8's 8 drives
  from seed 7, DELETEs only, one coordinator and no fault; it passes on every trace it drew, and with
  the twin (`revert-early`) the same draw finds the question's second trace in 32 states: DELETE w1's
  revert after its release restores drive 6, which DELETE w2 had counted toward its acknowledged
  quorum, leaving the initial value on 4 of the 8 drives.
- **§22.8's row.** Breadth-first at 4 drives on 2 hosts with 2 writes, a coordinator crash and a host
  failure: the cfg, with heal and cancels held still, and `sum-heal` and `sum-cancel`, with each on;
  with both on, by simulation only, in `three-faults`, where a third write may never reach the store.
  With 3 writes: breadth-first in the two mixes each counterexample needs, without faults
  (`three-deletes`, `three-puts`), since details/Settle.tla's three writes of any kind did not finish
  at 38 M states (DESIGN-DETAILS.md 2.3); with a crash and a host failure, by simulation
  (`three-faults`). At 6 drives on 3 hosts, 2 and 3 writes with a crash and a host failure: by
  simulation only (`six`, `six-three`), since details/Settle.tla did not finish there breadth-first at
  19 M states. At 8 drives: by simulation, at §22.8's own bounds with 3 writes, 2 coordinators and 2
  host failures (`wide`), and with 2 writes deeper (`eight`). HeldKeyReleased under weak fairness: on
  two DELETEs, whose keys rule (3) holds longest, and on one write beside a host failure and a crash
  (`live-deletes`, `live-hosts`).
- **Not run to the end.** Breadth-first at 4 drives with heal and cancels both on beside a crash and a
  host failure (stopped at 12 GB, past 138 M states, as above); at 6 or 8 drives; and at 3 writes with
  a crash or a host failure. Liveness beyond the two rows: two writes of either kind beside a host
  failure, without symmetry, was stopped unfinished at 4.2 M states to free the host. A simulation
  shows only that the behaviors it drew kept every invariant.

## IndexRollup.tla

§22.8's model of the search index's upkeep on one ref, on DESIGN-DETAILS.md section 1's rules under
owner decision 584's full entries (QD-1036): every entry is full or a tombstone and is taken as it
stands, a writer reuses any absorbed slot that is not its head and removes every absorbed large entry
at its next push, and the erasure's CLOSUREs rewrite each file that held a listed version, absorbed
slots included, in no order. The diff, its base, kept slots, composed merges and roll-ups went with
the invariant that held them, ChainsResolve, its twins (DiffOnListed, ReusePinned, CleanupReferenced,
MergeRemovesLarge) and three reach states. The cfg's CUT now lists d1 as its eraser read it
(CutVersion "read"); a CUT listing d1 as committed when it lands is the `cut-commit` ground. Every run
was on 2026-11-18 on 6 workers, on a host the build lanes were loading at a load average between 70
and 105 on 14 cores, so a time here is several times an idle host's. A breadth-first run on several
workers may count a few states more or fewer from one run to the next, and a twin's count is what TLC
had explored when it met its violation.

### The gate's run

`run-tlc.sh twins IndexRollup`, as model_test.go's TestIndexRollupMutantsFailTlc ran it at 68a26f8c.
modelled.yml records it. The model at its cfg's bounds and its liveness there (`run-tlc.sh model` and
`live`) were not run: the cfg's bounds do not finish breadth-first on a shared host, and the design
grounds below stand in for them.

```text
== PASS twin-NoEpochCheck: CutFences violated as it must, exit 12, 39 distinct states, depth 11, a trace of 6 states, 03s
== PASS twin-BuildIgnoresSet: CutFences violated as it must, exit 12, 44 distinct states, depth 9, a trace of 6 states, 04s
== PASS twin-EraseLiveFirst: ResultsHold violated as it must, exit 12, 195 distinct states, depth 11, a trace of 10 states, 03s
== PASS twin-EarlyComplete: ErasedUnreadable violated as it must, exit 12, 43 distinct states, depth 11, a trace of 10 states, 02s
== PASS twin-ClosureNoCas: ResultsHold violated as it must, exit 12, 224 distinct states, depth 12, a trace of 11 states, 03s
== PASS twin-EraseSkipsAbsorbed: ErasedUnreadable violated as it must, exit 12, 84 distinct states, depth 15, a trace of 12 states, 02s
== PASS twin-MergeIgnoresEpoch: EpochHolds violated as it must, exit 12, 84 distinct states, depth 16, a trace of 8 states, 03s
== PASS twin-MergeDropsTombstone: ResultsHold violated as it must, exit 12, 2006 distinct states, depth 11, a trace of 9 states, 05s
== PASS twin-ReuseUnabsorbed: ResultsHold violated as it must, exit 12, 208 distinct states, depth 8, a trace of 7 states, 03s
== PASS twin-RollupForgetsHeads: ResultsHold violated as it must, exit 12, 4502 distinct states, depth 12, a trace of 12 states, 08s
== PASS twin-MergeKeepsOld: OneVersionEach violated as it must, exit 12, 46 distinct states, depth 11, a trace of 11 states, 03s
== PASS twin-NoLockFence: RollsOnce violated as it must, exit 12, 92 distinct states, depth 16, a trace of 15 states, 02s
== PASS twin-NoOwnCas: ResultsHold violated as it must, exit 12, 38675 distinct states, depth 15, a trace of 13 states, 28s
== PASS twin-CleanupUnabsorbed: ResultsHold violated as it must, exit 12, 78 distinct states, depth 7, a trace of 7 states, 02s
== PASS twin-NoPromote: ResultsHold violated as it must, exit 12, 10189 distinct states, depth 15, a trace of 15 states, 08s
== PASS twin-NoPromoteLive: BucketsExact violated as it must, exit 12, 5436 distinct states, depth 17, a trace of 15 states, 04s
== PASS twin-PromoteBlind: ResultsHold violated as it must, exit 12, 1327403 distinct states, depth 20, a trace of 20 states, 13min 24s
== PASS twin-IndexSupersede: ResultsHold violated as it must, exit 12, 8486 distinct states, depth 15, a trace of 15 states, 07s
== PASS twin-LongLife: ResultsHold violated as it must, exit 12, 26257 distinct states, depth 15, a trace of 15 states, 07s
```

### Each twin's ground as its control

`run-tlc.sh control IndexRollup <Twin>`: the design at the twin's bounds, every invariant of the cfg
holding, so a twin's refusal is its broken rule's and not its ground's.

```text
== PASS control-NoEpochCheck: exit 0, 41 distinct states, depth 11, 02s
== PASS control-BuildIgnoresSet: exit 0, 41 distinct states, depth 11, 02s
== PASS control-EraseLiveFirst: exit 0, 250 distinct states, depth 14, 01s
== PASS control-EarlyComplete: exit 0, 41 distinct states, depth 11, 02s
== PASS control-ClosureNoCas: exit 0, 250 distinct states, depth 14, 02s
== PASS control-EraseSkipsAbsorbed: exit 0, 91 distinct states, depth 16, 02s
== PASS control-MergeIgnoresEpoch: exit 0, 91 distinct states, depth 16, 02s
== PASS control-MergeDropsTombstone: exit 0, 16803 distinct states, depth 23, 10s
== PASS control-ReuseUnabsorbed: exit 0, 1971 distinct states, depth 19, 02s
== PASS control-RollupForgetsHeads: exit 0, 16803 distinct states, depth 23, 12s
== PASS control-MergeKeepsOld: exit 0, 46 distinct states, depth 11, 02s
== PASS control-NoLockFence: exit 0, 96 distinct states, depth 17, 01s
== PASS control-NoOwnCas: exit 0, 286561 distinct states, depth 29, 07min 28s
== PASS control-CleanupUnabsorbed: exit 0, 2824 distinct states, depth 19, 03s
== PASS control-NoPromote: exit 0, 16803 distinct states, depth 23, 19s
== PASS control-NoPromoteLive: exit 0, 12203 distinct states, depth 24, 15s
```

### The design grounds

`run-tlc.sh ground IndexRollup <ground>` for rows of `run-tlc.sh list-grounds IndexRollup`: the two
reach states, each ending violated with its trace the witness; `cut-commit`; the erasure's narrow
grounds; liveness (BucketRolls and ErasureFinishes under weak fairness, without symmetry); two rollers
with a crash, a lapse and a foreign CUT; and the cfg's own bounds by seeded simulation, which shows
only that the behaviors it drew kept every invariant.

```text
== PASS ground-reach-absorbed-closure: NeverAbsorbedClosure violated as it must, exit 12, 82 distinct states, depth 14, a trace of 10 states, 01s
== PASS ground-reach-survives: NeverSurvives violated as it must, exit 12, 491 distinct states, depth 17, a trace of 14 states, 01s
== PASS ground-cut-commit: exit 0, 1787 distinct states, depth 24, 02s
== PASS ground-erase-restart-merge: exit 0, 46097 distinct states, depth 29, 16s
== PASS ground-erase-shared: exit 0, 51672 distinct states, depth 34, 18s
== PASS ground-erase-windows-unedited: exit 0, 61182 distinct states, depth 34, 37s
== PASS ground-erase-crash-backfill: exit 0, 214963 distinct states, depth 30, 57s
== PASS ground-live-rolls: exit 0, 3558 distinct states, depth 26, 17s
== PASS ground-live-erase: exit 0, 23757 distinct states, depth 27, 01min 20s
== PASS ground-live-windows: exit 0, 61182 distinct states, depth 34, 01min 51s
== PASS ground-rollers-epoch: exit 0, 1130471 distinct states, depth 35, 08min 32s
== PASS ground-cfg-simulation: exit 0, simulation, 1571928 states generated, 11min 44s
```

### The probe of details/IndexMerge.tla

`details/run-indexmerge.sh <track> IndexMergeProbe-RaceFenced`, at b6062207: step 4 in place with the
newer bucket's manifest replaced (question rollup-merge-race's option 1), which is not the design and
no part of the script's `all`, on full entries. It must pass.

```text
== PASS IndexMergeProbe-RaceFenced: tlc d8fb231, exit 0, 16838 distinct states, depth 24, 04s, 0 MB on disk at most
```
