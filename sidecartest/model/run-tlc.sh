#!/usr/bin/env bash
# Runs §22.8's model checks (D-TEST-10) with TLC: a model at its .cfg's bounds, which must pass;
# each twin, which breaks one rule of the design and must make TLC report the invariant that rule
# protects; the liveness properties under weak fairness; and, for a model whose cfg's bounds do not
# finish breadth-first on a shared host, the design grounds that do, each ending as its row says.
#
#   run-tlc.sh model <Spec> [Name=value ...]            the model, at its cfg's bounds or these
#   run-tlc.sh twins <Spec> [Name=value ...]            every twin of the model outside its parts, in turn
#   run-tlc.sh twins-<part> <Spec> [Name=value ...]     every twin of one of its parts, in turn
#   run-tlc.sh twin <Spec> <Twin> [Name=value ...]      one twin, of any part
#   run-tlc.sh control <Spec> <Twin> [Name=value ...]   the model at that twin's bounds, to pass
#   run-tlc.sh live <Spec> [Name=value ...]             liveness, without symmetry or view
#   run-tlc.sh live-<part> <Spec> [Name=value ...]      one part's liveness runs, each at its bounds
#   run-tlc.sh stories-<part> <Spec> [Name=value ...]   one part's stories, each at its bounds
#   run-tlc.sh grounds <Spec> [Name=value ...]          a model's design grounds, each as it must end
#   run-tlc.sh ground <Spec> <Ground> [Name=value ...]  one of them
#   run-tlc.sh list <Spec>                              every twin, of any part, and the invariant it must break
#   run-tlc.sh list-grounds <Spec>                      the grounds and what each must show
#   run-tlc.sh list-parts <Spec>                        each part's twins, stories and liveness runs
#
# A part is a group of a model's twins, stories and liveness runs that a gate needs apart from its other
# runs, so each of its groups is a mode of its own, which modelled.yml records on its own: EvsCommit's M10
# part runs as the purger's (purge), which M10's entry needs, and the drop extension's (drop), which only
# its exit needs (§22.10; QD-1116, QD-1119; parts_EvsCommit below). StoreSettle and IndexRollup have none.
#
# <Spec> is EvsCommit, StoreSettle or IndexRollup. A Name=value replaces a constant of the spec's
# cfg; Quiet=a+b leaves the named processes out (quiet_EvsCommit below; IndexRollup and StoreSettle
# hold theirs still by their own Still constants instead), and Script and Simulate shape a run further
# (with_constants below). Live mode runs a spec's liveness rows where it has them (lives_StoreSettle
# below), each at its bounds, and otherwise the cfg's. TLC names a command that runs tlc2.TLC, as in
#   TLC="java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC" run-tlc.sh model StoreSettle
# and TLC_FLAGS adds flags, as in TLC_FLAGS="-workers 8". Each run works in a fresh directory under
# TMPDIR, so no state or trace file lands beside the specs. TLC prints its revision first: name it
# with any result.
#
# exit: 0 every run did what it must; 1 one did not; 64 usage
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)

usage() {
  sed -n '7,19p' "$0" | sed 's/^# //' >&2
  exit 64
}

# Each twin, the invariant it must break, and the bounds it runs at in place of the cfg's, small
# enough that breadth-first search reaches the violation; a twin's run checks only its invariant.
# seq is one writer and one instance, each push answered before the next; tiny is a window of 2
# versions paging out one at a time, so a page-out fits in a short behavior; quiet_but holds still
# every part a twin's rule never reaches. A Script fixes the story of a twin whose violation lies
# past 30 steps, which open signing does not reach, and Simulate runs one by random simulation
# where even a story leaves too many interleavings to search.
#
# Three of the model's twins have no row, since no invariant can see them: NoTailCheck, as the
# model carries nothing a tail holds (a new epoch's tokens for paths created after the map's
# source); and NoFenceRule and ResolveIgnoresPending, as at the model's hour marks a statement has
# lapsed (5b) before its batch is old enough to evacuate, or its receipt or map is too old to pass
# (5h, 5e) before GC or a map's reclaim acts, so every attempt a fence would end is refused anyway,
# and a stalled one holds the key that Resolve's and the fence's head reads wait on. The slot rules
# of DESIGN-DETAILS 14.2 have their twins in details/EvsSlot.tla, this model's companion, run by
# details/run-slot.sh: here every slot is its own statement's and a killed evacuation run sends
# nothing, so no invariant here sees step 6 take another's object, or evacuation's origin, settle
# age or named DELETE broken.
seq_EvsCommit="Writers={w1} Instances={i1} Segments={s1} MaxAttempts=1 MaxFaults=0 MaxHour=0 MaxGeneration=1 MaxVersion=4"
tiny_EvsCommit="FoldTrigger=1 FoldSize=1 BaseRange=0 WindowLimit=2 WindowMax=3"
quiet_but() {
  local part kept out=""
  for part in reader fold collect evac gc lifecycle authority epoch cache stale parts slots uploads; do
    for kept in "$@"; do [ "$part" = "$kept" ] && continue 2; done
    out=${out:+$out+}$part
  done
  echo "Quiet=$out"
}
twins_EvsCommit() {
  local seq=$seq_EvsCommit tiny=$tiny_EvsCommit
  cat <<EOF
RestoreAfterShred      LifecycleHolds        $seq MaxPush=1 $(quiet_but lifecycle)
VersionRestarts        VersionsRise          $seq MaxPush=3 $(quiet_but)+gitref
PinFalls               PinsHold              $seq Writers={w1,w2} MaxPush=2 $(quiet_but authority)+gitref
NoPinCheck             PinsHold              $seq Writers={w1,w2} MaxPush=1 $(quiet_but authority)+gitref
LadderFork             OneLadder             $seq Writers={w1,w2,w3} MaxGeneration=2 MaxPush=1 $(quiet_but authority)+gitref
GitPathCas             GitTip                $seq Writers={w1,w2} MaxPush=2 $(quiet_but)+fileref
UnrecordedRefusal      OutcomesHold          $seq MaxAttempts=2 MaxPush=1 $(quiet_but lifecycle)+gitref
EarlyRefusalDrop       OutcomesHold          $seq Writers={w1,w2} MaxAttempts=2 MaxPush=2 $(quiet_but lifecycle)+gitref
AnswerDeletes          AnswersDeleteNothing  $seq Writers={w1,w2} Instances={i1,i2} MaxPush=2 $(quiet_but slots)+gitref
EvacuateBeforeIndex    ClosureHolds          $seq MaxPush=1 MaxHour=3 $(quiet_but evac)+gitref
GcNoFence              GcSafe                $seq MaxPush=2 MaxHour=3 MaxFaults=1 $(quiet_but gc uploads)+gitref+newrefstall
GcNoSecondCheck        GcSafe                $seq MaxPush=2 MaxHour=3 MaxFaults=1 $(quiet_but gc uploads)+gitref+newrefstall
PageOutUnfolded        NewestFound           $seq MaxPush=3 $tiny $(quiet_but)+gitref
StaleHorizon           FileCas               $seq Writers={w1,w2} Instances={i1,i2} MaxPush=3 $(quiet_but fold)+gitref Simulate=100 Traces=40000 Seed=1
ReaderStaleHorizon     ReadsServeNewest      $seq MaxPush=3 $(quiet_but reader fold)+gitref Script=X.create:X.write:D.create
NoIfMatchFold          NewestFound           $seq Instances={i1,i2} MaxPush=3 $(quiet_but fold)+gitref Script=X.create:X.write:D.create
NoRetryLookup          OutcomesHold          $seq Writers={w1,w2} Instances={i1,i2} MaxPush=3 $tiny $(quiet_but fold)+gitref Script=X.create:D.create:C.create
NoWindowWait           NewestFound           $seq MaxPush=5 MaxVersion=6 $tiny $(quiet_but fold collect)+gitref Script=X.create:X.remove:D.create:X.create:D.remove
FoldIgnoresWindow      NewestFound           $seq MaxPush=5 MaxVersion=6 $tiny $(quiet_but fold collect)+gitref Script=X.create:X.remove:D.create:X.create:D.remove
CachedRefusal          OutcomesHold          $seq Writers={w1,w2} MaxAttempts=2 MaxGeneration=2 MaxPush=3 MaxVersion=4 $(quiet_but authority epoch cache stale fold)+gitref Script=X.create:epoch:X.write Simulate=150 Traces=40000 Seed=1
CopyOverwrites         NewestFound           $seq Writers={w1,w2} MaxGeneration=2 MaxPush=4 MaxVersion=5 $(quiet_but authority epoch fold)+gitref+gkm+block Script=X.create:epoch:X.write:D.create
EOF
}

# EvsCommit's parts (QD-1116). Its M10 part, run story by story (F2Run) with the M2 part held at its
# start, splits between §22.10's gates for format 2: M10's entry needs "EvsCommit.tla with the purger"
# passing TLC, and its exit "the model's drop extension". So the purger's twins and stories (purge) and
# the drop extension's twins, stories and liveness (drop) are parts, each group run by a mode of its own
# (twins-purge, stories-purge, twins-drop, stories-drop, live-drop), which modelled.yml records apart, and
# twins runs the M2 part's alone.
parts_EvsCommit="purge drop"

# A part's twins run its stories: a purge story on the committing instance alone, which holds the
# purge's queue, and a drop story on two, whose late step 7s race the fence. PurgeUnseen breaks two
# rules at once, queueing a push's candidates before its commit is seen and deleting them with no
# reread of the newest version: either alone deletes nothing a version needs, since the reread keeps
# what a push that never committed did not replace, and a queue of seen commits holds only what they
# replaced.
purge_EvsCommit="F2Run=\"purgeA\" Instances={i1} F2MaxHour=3"
drop_EvsCommit="F2Run=\"dropB\""
twins_EvsCommit_purge() {
  cat <<EOF
PurgeNoAllowance       F2DeletesKeepRules    $purge_EvsCommit
PurgeIgnoresHold       F2DeletesKeepRules    $purge_EvsCommit
PurgeUnseen            F2Closure             $purge_EvsCommit
EvacDropsNewest        F2Closure             $purge_EvsCommit
EOF
}
twins_EvsCommit_drop() {
  cat <<EOF
DropNoFence            F2FenceHolds          $drop_EvsCommit
DropNoAgeCheck         F2Closure             $drop_EvsCommit
DropIgnoresHold        F2DeletesKeepRules    $drop_EvsCommit
EOF
}

# A part's stories, each small enough for breadth-first search: the purge stories on the committing
# instance alone and three long marks, enough for a record's evacuation, and the drop stories on two
# instances, whose late step 7s race the fence, and the cfg's four marks.
stories_EvsCommit_purge() {
  cat <<'STORIES'
purgeA   F2Run="purgeA" Instances={i1} F2MaxHour=3
purgeB   F2Run="purgeB" Instances={i1} F2MaxHour=3
purgeC   F2Run="purgeC" Instances={i1} F2MaxHour=3
purgeD   F2Run="purgeD" Instances={i1} F2MaxHour=3
purgeE   F2Run="purgeE" Instances={i1} F2MaxHour=3
STORIES
}
stories_EvsCommit_drop() {
  cat <<'STORIES'
dropA    F2Run="dropA"
dropB    F2Run="dropB"
dropC    F2Run="dropC"
STORIES
}

# A part's liveness runs, each under LiveSpec with the spec's properties (live_cfg), without symmetry or
# view. The drop extension's: F2DropsEnd, that every executing drop ends done, held or refused while no
# hold stands, under weak fairness on each drop story, on the one instance EVSB-M10-07 ran them on by
# hand (QD-1119); two instances, which EVSB-M10-07 deferred, are the review phase's. The purger has
# none: §22.8 names no liveness of it.
lives_EvsCommit_drop() {
  cat <<'LIVES'
dropA    F2Run="dropA" Instances={i1}
dropB    F2Run="dropB" Instances={i1}
dropC    F2Run="dropC" Instances={i1}
LIVES
}

# The spec's parts, empty for a spec with none.
spec_parts() {
  local parts=parts_$spec
  echo "${!parts:-}"
}

# Every twin of the spec, each of its parts' after its own, as list prints them and twin and control
# find them.
all_twins() {
  local part
  "twins_$spec"
  for part in $(spec_parts); do
    "twins_${spec}_$part"
  done
}

# StoreSettle's twins run breadth-first with PUTs and DELETEs mixed, at 4 drives on 2 hosts, 2 writes
# and one coordinator, as details/Settle.tla's twin configurations do (DESIGN-DETAILS.md 2.3), with a
# host failure, a crash, heal and cancels only where a twin's rule needs them. A twin that must break
# two invariants has a second row, named by its Twin value, a hyphen and a word (run_twin below):
# DeleteReleasesEarly breaks FI-30 itself, and DeleteReleasesEarly-Settled rule (3)'s own invariant.
small_StoreSettle="DriveCount=4 Writes={w1,w2} CoordinatorCount=1 HostFailures=0 CoordinatorCrashes=0"
twins_StoreSettle() {
  local small=$small_StoreSettle still='Still={"heal","cancel"}'
  cat <<EOF
ReleaseOnCancel              NoStaleQuorum        $small Still={"heal"}
NoDeadlineCheck              LateWritesNeverRead  $small $still
NoVersionCheck               NoStaleQuorum        $small $still
RevertBelowQuorumOnly        LateWritesNeverRead  $small $still
SettlerRevertsUnseen         NoStaleQuorum        $small HostFailures=1 CoordinatorCrashes=1 $still
HealMinority                 NoStaleQuorum        $small Still={"cancel"}
NoDriveLock                  NoStaleQuorum        $small $still
NoStamp                      NoStaleQuorum        $small MaxPuts=1 MaxDeletes=1 $still
DeleteReleasesEarly          NoStaleQuorum        $small HostFailures=1 $still
DeleteReleasesEarly-Settled  FailedDeleteSettled  $small $still
EOF
}

# IndexRollup's twins run breadth-first, each on the smallest ground that reaches what its rule
# protects, one roller unless the rule is the lock's, and the processes its rule never reaches held
# still. The erasure's run on d1's story. Section 1's (NoOwnCas, CleanupUnabsorbed, NoPromote,
# PromoteBlind, and IndexSupersede and LongLife for R5's pin and life) run on the grounds
# details/IndexMerge.tla's twin configurations run them on, with the erasure held still, and
# NoPromoteLive on the ground its live promotion was reached on there. Owner decision 584 (QD-1036)
# ended diffs, and with them the twins that broke a rule only a diff's base needed (DiffOnListed,
# ReusePinned, CleanupReferenced, MergeRemovesLarge) and the invariant they broke, ChainsResolve;
# NoOwnCas now loses a tombstone under a seq a merge has absorbed past, and CleanupUnabsorbed a large
# entry no merge has absorbed, each breaking ResultsHold.
twins_IndexRollup() {
  local one="Rollers={r1} MaxCrashes=0 MaxLapses=0 MaxRestarts=0 ForeignCuts=0 BigDocs={}"
  local d1="$one Documents={\"d1\"} Skew=FALSE"
  local d12="$one Documents={\"d1\",\"d2\"} Events=2 Skew=FALSE"
  local d2="$one Documents={\"d2\"} Skew=FALSE"
  local d3="$one Documents={\"d3\"} Events=2 Skew=TRUE Still={\"erase\"}"
  local quiet='Still={"rollup","tick","backfill","merge"}'
  cat <<EOF
NoEpochCheck           CutFences            $d1 Events=1 $quiet
BuildIgnoresSet        CutFences            $d1 Events=1 $quiet
EraseLiveFirst         ResultsHold          $d12 $quiet
EarlyComplete          ErasedUnreadable     $d1 Events=1 $quiet
ClosureNoCas           ResultsHold          $d12 $quiet
EraseSkipsAbsorbed     ErasedUnreadable     $d1 Events=1 Still={"rollup","tick","backfill"}
MergeIgnoresEpoch      EpochHolds           $d1 Events=1 Still={"rollup","tick","backfill"}
MergeDropsTombstone    ResultsHold          $d3
ReuseUnabsorbed        ResultsHold          $one Documents={"d2","d3"} Events=2 Skew=FALSE Still={"rollup","erase","tick"}
RollupForgetsHeads     ResultsHold          $d3
MergeKeepsOld          OneVersionEach       $d2 Events=2 Still={"rollup","erase","tick","backfill"}
NoLockFence            RollsOnce            $one Rollers={r1,r2} MaxLapses=1 Documents={"d3"} Events=1 Skew=FALSE Still={"erase","backfill","merge"}
NoOwnCas               ResultsHold          $one Documents={"d2","d3"} Events=3 Skew=FALSE BigDocs={"d2"} MaxRestarts=1 Still={"rollup","erase","tick"}
CleanupUnabsorbed      ResultsHold          $one Documents={"d2","d3"} Events=2 Skew=FALSE BigDocs={"d3"} Still={"rollup","erase","tick"}
NoPromote              ResultsHold          $d3
NoPromoteLive          BucketsExact         $one Documents={"d2"} Events=3 Skew=TRUE Still={"backfill","erase"}
PromoteBlind           ResultsHold          $one Documents={"d2","d3"} Events=3 Skew=TRUE Still={"erase"}
IndexSupersede         ResultsHold          $d3
LongLife               ResultsHold          $d3
EOF
}

# IndexRollup's design grounds. Its cfg's bounds do not finish breadth-first on a shared host, so the
# design is also checked on narrower grounds, each holding still what it leaves out, and each must end
# as its row says: "pass", every invariant of the cfg holding; "live", BucketRolls and ErasureFinishes
# holding under weak fairness, without symmetry; or a predicate violated, its trace the witness. Those
# predicates are the spec's reach states (Never...), which the joined rules must reach so that a ground
# passing there is not vacuous: a CLOSURE of an absorbed slot, and an edit that landed between the
# eraser's read and its CUT standing once the erasure completes. Each twin's ground runs as its
# control (control mode). Smallest first: the reach states; a CUT that lists d1 as committed when it
# lands, the cfg's listing it as its eraser read it (cut-commit: "commit" was the cfg's while diffs
# stood, since a CUT as read took a live diff's base; owner decision 584 ended them); the erasure's
# narrow grounds (a writer restart beside merges, d1 and d2 sharing slots, d1 unedited across three
# windows, the eraser's crash and a foreign CUT beside the backfiller); the
# liveness grounds; two rollers with a crash, a lapse and a foreign CUT; the cfg's own bounds by seeded
# simulation, which shows only that the behaviors it drew (Traces on each worker) kept every invariant;
# then the widest, which take longest: the erasure's crash and restart grounds with merges and the
# backfiller together, DESIGN-DETAILS section 1.3's two that did not finish on details/IndexMerge.tla
# (d2 edited three times by both writers, with a restart, and across three windows), and d1 edited
# across three windows.
grounds_IndexRollup() {
  local one="Rollers={r1} MaxCrashes=0 MaxLapses=0 MaxRestarts=0 ForeignCuts=0 BigDocs={}"
  local d1="$one Documents={\"d1\"}"
  local rollers="Rollers={r1,r2} MaxCrashes=1 MaxLapses=1 MaxRestarts=0 ForeignCuts=1 BigDocs={} Documents={\"d3\"}"
  local quiet='Still={"rollup","tick","backfill","merge"}'
  cat <<EOF
reach-absorbed-closure  NeverAbsorbedClosure  $d1 Events=1 Skew=FALSE Still={"rollup","tick","backfill"}
reach-survives          NeverSurvives         $d1 Events=2 Skew=FALSE $quiet
cut-commit              pass                  $d1 Events=2 Skew=FALSE Still={"rollup","tick","backfill"} CutVersion="commit"
erase-restart-merge     pass                  $d1 Events=2 Skew=FALSE MaxRestarts=1 Still={"rollup","tick","backfill"}
erase-shared            pass                  $one Documents={"d1","d2"} Events=4 Skew=FALSE Still={"rollup","tick","backfill"}
erase-windows-unedited  pass                  $d1 Events=1 Skew=TRUE Still={}
erase-crash-backfill    pass                  $d1 Events=2 Skew=FALSE MaxCrashes=1 ForeignCuts=1 Still={"rollup","tick","merge"}
live-rolls              live                  $rollers Events=1 Skew=FALSE Still={"erase","backfill"}
live-erase              live                  $d1 Events=2 Skew=FALSE MaxCrashes=1 ForeignCuts=1 Still={"rollup","tick","backfill"}
live-windows            live                  $d1 Events=1 Skew=TRUE Still={}
rollers-epoch           pass                  $rollers Events=2 Skew=TRUE Still={"erase"}
cfg-simulation          pass                  Simulate=150 Traces=2500 Seed=1
erase-crash             pass                  $d1 Events=2 Skew=FALSE MaxCrashes=1 ForeignCuts=1 Still={"rollup","tick"}
erase-restart           pass                  $d1 Events=2 Skew=FALSE MaxRestarts=1 Still={"rollup","tick"}
edits-restart           pass                  $one Documents={"d2"} Events=3 Skew=FALSE MaxRestarts=1 Still={"rollup","erase","tick"}
edits-windows           pass                  $one Documents={"d2"} Events=3 Skew=TRUE Still={"erase"}
erase-windows           pass                  $d1 Events=2 Skew=TRUE Still={}
EOF
}

# StoreSettle's design grounds. §22.8's row asks for breadth-first runs at 4 drives on 2 hosts and at 6
# on 3, each with 2 and 3 writes, a coordinator crash and a host failure, and for simulation at 8 drives
# with 3 writes and 2 coordinators. Its cfg is the first, with heal and cancels held still; the rest do
# not finish breadth-first on a shared host (DESIGN-DETAILS.md 2.3 stopped details/Settle.tla at 6
# drives with two writes at 19 M states, and at 4 drives with three writes of any kind at 38 M), so
# they are bounded as details/Settle.tla's configurations bound them, and each must end as its row says:
# "pass", every invariant of the cfg holding; "live", HeldKeyReleased under weak fairness without
# symmetry (lives_StoreSettle below, which live mode runs); or an invariant violated, its trace the
# witness. In order: the two traces of question evs-models-settle-stalled-deletes (QD-744), each
# passing at its own bounds and refused there with twin DeleteReleasesEarly, so that a pass by
# simulation is not one its seed could not fail. The first's bounds are the cfg's with heal and cancels
# on, whose state outgrows the 12 GB a run may hold on a shared host (stopped twice past 138 M states,
# no invariant violated), so heal and cancels each run beside the cfg's crash and host failure, and
# both together by simulation with three-faults. Then the liveness rows; three writes in the two mixes
# each counterexample needs, a PUT with two DELETEs and two PUTs with a DELETE, breadth-first and
# without faults; then by simulation, which shows only that the behaviors it drew (Traces on each
# worker) kept every invariant: three writes with a crash and a host failure at 4 drives, two and three
# writes at 6 drives on 3 hosts, two writes at 8 drives deeper, and §22.8's own bounds, 8 drives, 3
# writes, 2 coordinators and 2 host failures.
grounds_StoreSettle() {
  local deletes="CoordinatorCount=1 HostFailures=0 CoordinatorCrashes=0 MaxPuts=0"
  local three="Writes={w1,w2,w3} CoordinatorCount=1 HostFailures=0 CoordinatorCrashes=0"
  local any="Writes={w1,w2,w3} MaxPuts=3 MaxDeletes=3 Still={}"
  cat <<EOF
sum-heal           pass           Still={"cancel"}
sum-cancel         pass           Still={"heal"}
sum-early          NoStaleQuorum  Still={} Twin="DeleteReleasesEarly"
revert             pass           DriveCount=8 $deletes Simulate=60 Traces=50000 Seed=7
revert-early       NoStaleQuorum  DriveCount=8 $deletes Simulate=60 Traces=50000 Seed=7 Twin="DeleteReleasesEarly"
EOF
  lives_StoreSettle | while read -r name bounds; do
    printf '%-18s %-14s %s\n' "live-$name" live "$bounds"
  done
  cat <<EOF
three-deletes      pass           $three MaxPuts=1 MaxDeletes=2
three-puts         pass           $three MaxPuts=2 MaxDeletes=1
three-faults       pass           $any Simulate=70 Traces=50000 Seed=4
six                pass           DriveCount=6 Still={} Simulate=70 Traces=50000 Seed=3
six-three          pass           DriveCount=6 $any Simulate=70 Traces=50000 Seed=5
eight              pass           DriveCount=8 Still={} Simulate=90 Traces=50000 Seed=2
wide               pass           DriveCount=8 HostFailures=2 $any Simulate=60 Traces=100000 Seed=1
EOF
}

# StoreSettle's liveness runs: HeldKeyReleased under weak fairness, without symmetry or view, so at
# bounds narrower than its cfg's, as details/Settle.tla's liveness configurations run it: two DELETEs,
# whose keys rule (3) holds longest; and one write of either kind beside a host failure and a crash the
# settler settles once the host comes back. Live mode runs each row; a spec without such a table runs
# its liveness at its cfg's bounds.
lives_StoreSettle() {
  cat <<'EOF'
deletes  CoordinatorCount=1 HostFailures=0 CoordinatorCrashes=0 MaxPuts=0
hosts    Writes={w1} MaxPuts=1 MaxDeletes=1
EOF
}

properties_EvsCommit="RemovalGates DueEpochCommits F2DropsEnd"
properties_StoreSettle="HeldKeyReleased"
properties_IndexRollup="BucketRolls ErasureFinishes"

# Quiet=a+b leaves processes out of a run: a module extending the spec holds each named part still
# by an action constraint, so the spec stays the design's. A run with any part quiet covers less,
# and its report must say which. newrefstall leaves out a stalled first commit to a ref with no
# head, which segment GC does not fence (a question raised on §11.13's orphan GC row).
quiet_EvsCommit() {
  cat <<'EOF'
reader     reader' = reader
fold       foldJob' = foldJob
collect    collector' = collector
evac       evacuator' = evacuator
gc         gc' = gc
lifecycle  repo' = repo
authority  rev' = rev /\ proj' = proj /\ (epoch' = epoch \/ epoch' = <<>>)
epoch      pmap' = pmap
cache      cache' = cache
stale      pushCount' > pushCount => push'[pushCount'].base = head[push'[pushCount'].ref].version
parts      pushCount' > pushCount => push'[pushCount'].kind # "parts"
slots      pushCount' > pushCount => ~push'[pushCount'].newSlot
uploads    pushCount' > pushCount => push'[pushCount'].seg = NoSegment
gitref     pushCount' > pushCount => push'[pushCount'].ref # GitRef
fileref    pushCount' > pushCount => push'[pushCount'].ref # FileRef
newrefstall \A r \in Refs : heldBy[r] = NoHolder /\ heldBy'[r] # NoHolder => head[r].version + head[r].fence > 0
gkm        epoch' = epoch \/ epoch' = <<>>
copy       copyJob' = copyJob
block      \A r \in Refs : blockLive'[r] => blockLive[r]
EOF
}

# IndexRollup has no quiet parts: its Still constant holds processes still inside the spec.
quiet_IndexRollup() {
  :
}

# Nor has StoreSettle: its Still constant holds heal or cancels still, and MaxPuts and MaxDeletes bound
# the writes the store takes of each kind.
quiet_StoreSettle() {
  :
}

# The cfg with each Name=value replacing that constant's line; an unknown name is refused. Quiet
# names parts to leave out, gathered for quieten. Simulate=<depth> runs TLC's random simulation in
# place of breadth-first search, at most Traces=<n> behaviors on each worker from Seed=<s>, which
# repeats exactly only on one worker: for a twin whose violation lies deeper than search reaches it
# finds a trace, and for a control it shows only that those behaviors kept every invariant.
# Script=X.create:X.remove:epoch fixes what each statement signed in turn changes, its path and
# operation or a PATH_EPOCH, so search covers every interleaving of one story.
quiet_parts="" sim_depth="" sim_traces="" sim_seed="" script=""
with_constants() {
  local cfg=$1 pair name value
  shift
  for pair in "$@"; do
    name=${pair%%=*}
    value=${pair#*=}
    case $name in
      Quiet) quiet_parts=${quiet_parts:+$quiet_parts+}$value; continue ;;
      Simulate) sim_depth=$value; continue ;;
      Traces) sim_traces=$value; continue ;;
      Seed) sim_seed=$value; continue ;;
      Script) script=$value; continue ;;
    esac
    if ! grep -q "^    $name = " "$cfg"; then
      echo "run-tlc.sh: $spec.cfg has no constant $name" >&2
      exit 64
    fi
    sed "s|^    $name = .*|    $name = $value|" "$cfg" > "$cfg.next" && mv "$cfg.next" "$cfg"
  done
}

# The cfg's INVARIANT section, one line or indented lines below it, replaced by the given lines.
replace_invariants() {
  local cfg=$1 lines=$2
  awk -v lines="$lines" '
    /^INVARIANT/ { skip = 1; if (lines != "") { print "INVARIANT"; print lines }; next }
    skip && /^    / { next }
    { skip = 0; print }
  ' "$cfg" > "$cfg.next" && mv "$cfg.next" "$cfg"
}

# With parts quiet, writes MC.tla, which extends the spec and holds those parts still, and has the
# cfg constrain every step by it; the run then checks MC.
quieten() {
  local cfg=$1 part conj body="" item story=""
  module=$spec
  [ -n "$quiet_parts$script" ] || return 0
  for part in ${quiet_parts//+/ }; do
    conj=$("quiet_$spec" | awk -v p="$part" '$1 == p { $1 = ""; sub(/^ +/, ""); print }')
    [ -n "$conj" ] || { echo "run-tlc.sh: $spec has no quiet part $part" >&2; exit 64; }
    body="$body    /\\ $conj"$'\n'
  done
  if [ -n "$script" ]; then
    for item in ${script//:/ }; do
      story="${story:+$story, }<<\"${item%%.*}\", \"${item#*.}\">>"
    done
    body="$body    /\\ pushCount' > pushCount => Signed(pushCount')"$'\n'
    story="Story == <<$story>>
Signed(k) ==
    /\\ k <= Len(Story)
    /\\ IF Story[k][1] = \"epoch\" THEN push'[k].kind = \"epoch\"
       ELSE \\E c \\in push'[k].changes : c.path = Story[k][1] /\\ c.op = Story[k][2]
"
  fi
  printf -- '---- MODULE MC ----\nEXTENDS %s\n%sQuiet ==\n%s====\n' "$spec" "$story" "$body" \
    > "$work/MC.tla"
  echo "ACTION_CONSTRAINT Quiet" >> "$cfg"
  module=MC
}

# One TLC run; prints its output and a summary line, and says whether it ended as expected: a pass,
# or the named invariant violated.
check() {
  local label=$1 cfg=$2 expect=$3 out=$work/$1.out code violated distinct depth generated took
  local search="" facts
  quieten "$cfg"
  if [ -n "$sim_depth" ]; then
    search="-simulate num=${sim_traces:-10000000} -depth $sim_depth -seed ${sim_seed:-1}"
  fi
  local shown
  shown=$(grep -v '^\\\*' "$cfg" | tr '\n' ' ' | sed 's/  */ /g')
  shown="$shown${quiet_parts:+ Quiet $quiet_parts}${script:+ Script $script}"
  echo "== $label: $shown${search:+ $search}"
  # shellcheck disable=SC2086
  (cd "$work" && $TLC ${TLC_FLAGS:-} $search -config "$cfg" "$module.tla") 2>&1 | tee "$out"
  code=${PIPESTATUS[0]}
  violated=$(sed -n 's/^Error: Invariant \(.*\) is violated.*/\1/p' "$out" | head -1)
  took=$(sed -n 's/^Finished in \(.*\) at .*/\1/p' "$out" | tail -1)
  if [ -n "$search" ]; then
    generated=$(sed -n 's/^The number of states generated: \([0-9,]*\).*/\1/p' "$out" | tail -1)
    facts="exit $code, simulation, $generated states generated"
  else
    distinct=$(sed -n 's/.* \([0-9,]*\) distinct states found.*/\1/p' "$out" | tail -1)
    depth=$(sed -n 's/^The depth of the complete state graph search is \([0-9]*\).*/\1/p' "$out" \
      | tail -1)
    facts="exit $code, ${distinct:-?} distinct states, depth ${depth:-?}"
  fi
  [ -z "$violated" ] || facts="$facts, a trace of $(grep -c '^State [0-9]*:' "$out") states"
  facts="$facts, ${took:-?}"
  if [ "$expect" = pass ]; then
    if [ "$code" -eq 0 ]; then
      echo "== PASS $label: $facts"
      return 0
    fi
    echo "== FAIL $label: $facts${violated:+, $violated violated}"
    return 1
  fi
  if [ "$code" -ne 0 ] && [ "$violated" = "$expect" ]; then
    echo "== PASS $label: $expect violated as it must, $facts"
    return 0
  fi
  echo "== FAIL $label: expected $expect violated, got $facts${violated:+, $violated violated}"
  return 1
}

# A twin's row is named by its Twin value, or by that value, a hyphen and a word for a twin's second
# row, which holds it to a second invariant.
run_twin() {
  local twin=$1 invariant=$2 cfg
  shift 2
  quiet_parts="" sim_depth="" sim_traces="" sim_seed="" script=""
  cfg=$work/twin-$twin.cfg
  cp "$here/$spec.cfg" "$cfg"
  with_constants "$cfg" "Twin=\"${twin%%-*}\"" "$@"
  replace_invariants "$cfg" "    $invariant"
  check "twin-$twin" "$cfg" "$invariant"
}

# The cfg rewritten for liveness: no invariants, no symmetry or view, LiveSpec and the spec's
# properties.
live_cfg() {
  local cfg=$1 props=properties_$spec prop
  replace_invariants "$cfg" ""
  {
    grep -v '^SPECIFICATION\|^SYMMETRY\|^VIEW' "$cfg"
    echo "SPECIFICATION LiveSpec"
    echo "PROPERTY"
    for prop in ${!props}; do echo "    $prop"; done
  } > "$cfg.next" && mv "$cfg.next" "$cfg"
}

# One design ground at its bounds, ending as its row says: pass, live, or the named predicate violated.
run_ground() {
  local ground=$1 expect=$2 cfg
  shift 2
  quiet_parts="" sim_depth="" sim_traces="" sim_seed="" script=""
  cfg=$work/ground-$ground.cfg
  cp "$here/$spec.cfg" "$cfg"
  with_constants "$cfg" "$@"
  case $expect in
    pass) check "ground-$ground" "$cfg" pass ;;
    live) live_cfg "$cfg" && check "ground-$ground" "$cfg" pass ;;
    *) replace_invariants "$cfg" "    $expect" && check "ground-$ground" "$cfg" "$expect" ;;
  esac
}

# The whole body is parsed before it runs, so editing this file never reaches a run in progress.
main() {
  [ $# -ge 2 ] || usage
  mode=$1
  spec=$2
  shift 2
  case $spec in EvsCommit|StoreSettle|IndexRollup) ;; *) usage ;; esac
  if [ "$mode" = list ]; then
    all_twins
    exit 0
  fi
  if [ "$mode" = list-parts ]; then
    for part in $(spec_parts); do
      "twins_${spec}_$part" | awk -v p="$part" '{ names = names " " $1 } END { print p " twins" names }'
      "stories_${spec}_$part" | awk -v p="$part" '{ names = names " " $1 } END { print p " stories" names }'
      if declare -F "lives_${spec}_$part" > /dev/null; then
        "lives_${spec}_$part" | awk -v p="$part" '{ names = names " " $1 } END { print p " lives" names }'
      fi
    done
    exit 0
  fi
  case $mode in
    list-grounds|grounds|ground)
      declare -F "grounds_$spec" > /dev/null || { echo "run-tlc.sh: $spec has no design grounds" >&2; exit 64; }
      ;;
    twins-*|stories-*|live-*)
      part=${mode#*-}
      case " $(spec_parts) " in
        *" $part "*) ;;
        *) echo "run-tlc.sh: $spec has no part $part" >&2; exit 64 ;;
      esac
      if [ "${mode%%-*}" = live ] && ! declare -F "lives_${spec}_$part" > /dev/null; then
        echo "run-tlc.sh: $spec's part $part has no liveness runs" >&2
        exit 64
      fi
      ;;
  esac
  if [ "$mode" = list-grounds ]; then
    "grounds_$spec"
    exit 0
  fi
  : "${TLC:?set TLC to a command that runs tlc2.TLC, as in TLC=\"java -cp tla2tools.jar tlc2.TLC\"}"

  work=$(mktemp -d "${TMPDIR:-/tmp}/run-tlc.XXXXXX") || exit 1
  trap 'rm -rf "$work"' EXIT
  cp "$here/$spec.tla" "$work/"

  failed=0
  case $mode in
    model)
      cfg=$work/model.cfg
      cp "$here/$spec.cfg" "$cfg"
      with_constants "$cfg" "$@"
      check model "$cfg" pass || failed=1
      ;;
    live)
      if declare -F "lives_$spec" > /dev/null; then
        while read -r name bounds; do
          quiet_parts="" sim_depth="" sim_traces="" sim_seed="" script=""
          cfg=$work/live-$name.cfg
          cp "$here/$spec.cfg" "$cfg"
          # shellcheck disable=SC2086
          with_constants "$cfg" $bounds "$@"
          live_cfg "$cfg"
          check "live-$name" "$cfg" pass || failed=1
        done < <("lives_$spec")
      else
        cfg=$work/live.cfg
        cp "$here/$spec.cfg" "$cfg"
        with_constants "$cfg" "$@"
        live_cfg "$cfg"
        check live "$cfg" pass || failed=1
      fi
      ;;
    live-*)
      while read -r name bounds; do
        quiet_parts="" sim_depth="" sim_traces="" sim_seed="" script=""
        cfg=$work/live-$name.cfg
        cp "$here/$spec.cfg" "$cfg"
        # shellcheck disable=SC2086
        with_constants "$cfg" $bounds "$@"
        live_cfg "$cfg"
        check "live-$name" "$cfg" pass || failed=1
      done < <("lives_${spec}_$part")
      ;;
    twin|control)
      [ $# -ge 1 ] || usage
      want=$1
      shift
      line=$(all_twins | awk -v t="$want" '$1 == t')
      [ -n "$line" ] || { echo "run-tlc.sh: $spec has no twin $want" >&2; exit 64; }
      read -r _ invariant bounds <<< "$line"
      if [ "$mode" = twin ]; then
        # shellcheck disable=SC2086
        run_twin "$want" "$invariant" $bounds "$@" || failed=1
      else
        cfg=$work/control-$want.cfg
        cp "$here/$spec.cfg" "$cfg"
        # shellcheck disable=SC2086
        with_constants "$cfg" $bounds "$@"
        check "control-$want" "$cfg" pass || failed=1
      fi
      ;;
    stories-*)
      while read -r story bounds; do
        quiet_parts="" sim_depth="" sim_traces="" sim_seed="" script=""
        cfg=$work/story-$story.cfg
        cp "$here/$spec.cfg" "$cfg"
        # shellcheck disable=SC2086
        with_constants "$cfg" $bounds "$@"
        check "story-$story" "$cfg" pass || failed=1
      done < <("stories_${spec}_$part")
      ;;
    twins|twins-*)
      table=twins_$spec
      [ "$mode" = twins ] || table=twins_${spec}_$part
      while read -r twin invariant bounds; do
        # shellcheck disable=SC2086
        run_twin "$twin" "$invariant" $bounds "$@" || failed=1
      done < <("$table")
      ;;
    grounds|ground)
      rows=$("grounds_$spec")
      if [ "$mode" = ground ]; then
        [ $# -ge 1 ] || usage
        rows=$(awk -v g="$1" '$1 == g' <<< "$rows")
        [ -n "$rows" ] || { echo "run-tlc.sh: $spec has no ground $1" >&2; exit 64; }
        shift
      fi
      while read -r ground expect bounds; do
        # shellcheck disable=SC2086
        run_ground "$ground" "$expect" $bounds "$@" || failed=1
      done <<< "$rows"
      ;;
    *)
      usage
      ;;
  esac
  return $failed
}

main "$@"; exit $?
