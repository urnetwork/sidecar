#!/usr/bin/env bash
# Runs §22.8's model checks (D-TEST-10) with TLC: a model at its .cfg's bounds, which must pass;
# each twin, which breaks one rule of the design and must make TLC report the invariant that rule
# protects; and the liveness properties under weak fairness.
#
#   run-tlc.sh model <Spec> [Name=value ...]          the model, at its cfg's bounds or these
#   run-tlc.sh twins <Spec> [Name=value ...]          every twin of the model, in turn
#   run-tlc.sh twin <Spec> <Twin> [Name=value ...]    one twin
#   run-tlc.sh control <Spec> <Twin> [Name=value ...] the model at that twin's bounds, to pass
#   run-tlc.sh live <Spec> [Name=value ...]           liveness, without symmetry or view
#   run-tlc.sh stories <Spec> [Name=value ...]        EvsCommit's M10 stories, each at its bounds
#   run-tlc.sh list <Spec>                            the twins and the invariant each must break
#
# <Spec> is EvsCommit, StoreSettle or IndexRollup. A Name=value replaces a constant of the spec's
# cfg; Quiet=a+b leaves the named processes out (quiet_EvsCommit below; IndexRollup holds its
# processes still by its own Still constant instead), and Script and Simulate shape a run further
# (with_constants below). TLC names a command that runs tlc2.TLC, as in
#   TLC="java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC" run-tlc.sh model StoreSettle
# and TLC_FLAGS adds flags, as in TLC_FLAGS="-workers 8". Each run works in a fresh directory under
# TMPDIR, so no state or trace file lands beside the specs. TLC prints its revision first: name it
# with any result.
#
# exit: 0 every run did what it must; 1 one did not; 64 usage
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)

usage() {
  sed -n '6,12p' "$0" | sed 's/^# //' >&2
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
# and a stalled one holds the key that Resolve's and the fence's head reads wait on.
seq_EvsCommit="Writers={w1} Instances={i1} Segments={s1} MaxAttempts=1 MaxFaults=0 MaxHour=0 MaxGeneration=1 MaxVersion=4"
# The M10 part's twins run its stories (F2Run): a purge story on the committing instance alone, which
# holds the purge's queue, and a drop story on two, whose late step 7s race the fence. PurgeUnseen
# breaks two rules at once, queueing a push's candidates before its commit is seen and deleting them
# with no reread of the newest version: either alone deletes nothing a version needs, since the reread
# keeps what a push that never committed did not replace, and a queue of seen commits holds only what
# they replaced.
purge_EvsCommit="F2Run=\"purgeA\" Instances={i1} F2MaxHour=3"
drop_EvsCommit="F2Run=\"dropB\""
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
  local seq=$seq_EvsCommit tiny=$tiny_EvsCommit m10purge=$purge_EvsCommit m10drop=$drop_EvsCommit
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
PurgeNoAllowance       F2DeletesKeepRules    $m10purge
PurgeIgnoresHold       F2DeletesKeepRules    $m10purge
PurgeUnseen            F2Closure             $m10purge
EvacDropsNewest        F2Closure             $m10purge
DropNoFence            F2FenceHolds          $m10drop
DropNoAgeCheck         F2Closure             $m10drop
DropIgnoresHold        F2DeletesKeepRules    $m10drop
EOF
}

# The design fails NoStaleQuorum once two DELETEs on a key stall or revert late, a question raised
# on §19.6's rule (3), so these twins run without DELETEs, at 4 drives on 2 hosts and one
# coordinator, with a host failure, a crash, heal and cancel only where a twin's rule needs them.
small_StoreSettle="DriveCount=4 Writes={w1,w2} CoordinatorCount=1 HostFailures=0 CoordinatorCrashes=0"
twins_StoreSettle() {
  local small=$small_StoreSettle
  cat <<EOF
ReleaseOnCancel        NoStaleQuorum        $small Quiet=deletes+heal
NoDeadlineCheck        LateWritesNeverRead  $small Quiet=deletes+heal+cancel
NoVersionCheck         NoStaleQuorum        $small Quiet=deletes+heal+cancel
RevertBelowQuorumOnly  LateWritesNeverRead  $small Quiet=deletes+heal+cancel
SettlerRevertsUnseen   NoStaleQuorum        $small HostFailures=1 CoordinatorCrashes=1 Quiet=deletes+heal+cancel
HealMinority           NoStaleQuorum        $small Quiet=deletes+cancel
NoDriveLock            NoStaleQuorum        $small Quiet=deletes+heal+cancel
EOF
}

# IndexRollup's twins run breadth-first, each on the smallest ground that reaches what its rule
# protects, one roller unless the rule is the lock's, and the processes its rule never reaches held
# still. The erasure's run on d1's story. Section 1's (NoOwnCas, ReusePinned, CleanupReferenced,
# MergeRemovesLarge, NoPromote, PromoteBlind, and IndexSupersede and LongLife for R5's pin and life)
# run on the grounds DESIGN-DETAILS.md section 1.3 ran them on in details/IndexMerge.tla, with the
# erasure held still, and NoPromoteLive on the ground its live promotion was reached on there.
# CutVersion="read" is not a twin but a finding: a CUT listing what its eraser read lets a CLOSURE
# take the base of a diff that landed before the CUT at a version it does not list, which TLC refuses
# with ChainsResolve violated on DiffOnListed's ground (question
# search-m10-46-erased-base-of-a-live-diff), and the cfg runs "commit".
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
DiffOnListed           ChainsResolve        $d1 Events=2 $quiet
EraseSkipsAbsorbed     ErasedUnreadable     $d1 Events=1 Still={"rollup","tick","backfill"}
MergeIgnoresEpoch      EpochHolds           $d1 Events=1 Still={"rollup","tick","backfill"}
MergeDropsTombstone    ResultsHold          $d3
ReuseUnabsorbed        ResultsHold          $one Documents={"d2","d3"} Events=2 Skew=FALSE Still={"rollup","erase","tick","bfdiff"}
RollupForgetsHeads     ResultsHold          $d3
MergeKeepsOld          OneVersionEach       $d2 Events=2 Still={"rollup","erase","tick","backfill"}
NoLockFence            RollsOnce            $one Rollers={r1,r2} MaxLapses=1 Documents={"d3"} Events=1 Skew=FALSE Still={"erase","backfill","merge"}
NoOwnCas               ChainsResolve        $d2 Events=3 MaxRestarts=1 Still={"backfill","rollup","erase","tick"}
ReusePinned            ChainsResolve        $d2 Events=4 Still={"rollup","erase","tick","bfdiff"}
CleanupReferenced      ChainsResolve        $d2 Events=4 BigDocs={"d2"} Still={"rollup","erase","tick","bfdiff"}
MergeRemovesLarge      ChainsResolve        $d2 Events=4 BigDocs={"d2"} Still={"rollup","erase","tick","bfdiff"}
NoPromote              ResultsHold          $d3
NoPromoteLive          BucketsExact         $one Documents={"d2"} Events=3 Skew=TRUE Still={"backfill","erase"}
PromoteBlind           ResultsHold          $one Documents={"d2","d3"} Events=3 Skew=TRUE Still={"erase"}
IndexSupersede         ResultsHold          $d3
LongLife               ResultsHold          $d3
EOF
}

properties_EvsCommit="RemovalGates DueEpochCommits F2DropsEnd"

# EvsCommit's M10 part runs story by story (F2Run), each small enough for breadth-first search: the
# purge stories on the committing instance alone and three long marks, enough for a record's
# evacuation, the drop stories on two instances, whose late step 7s race the fence, and four marks.
stories_EvsCommit() {
  cat <<'STORIES'
purgeA   F2Run="purgeA" Instances={i1} F2MaxHour=3
purgeB   F2Run="purgeB" Instances={i1} F2MaxHour=3
purgeC   F2Run="purgeC" Instances={i1} F2MaxHour=3
purgeD   F2Run="purgeD" Instances={i1} F2MaxHour=3
purgeE   F2Run="purgeE" Instances={i1} F2MaxHour=3
dropA    F2Run="dropA"
dropB    F2Run="dropB"
dropC    F2Run="dropC"
STORIES
}
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

quiet_StoreSettle() {
  cat <<'EOF'
deletes    kind' = kind
puts       \A w \in Writes : phase[w] = "waiting" /\ phase'[w] = "running" => kind'[w] = "delete"
heal       healing' = healing
cancel     cancelled' = cancelled
EOF
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

run_twin() {
  local twin=$1 invariant=$2 cfg
  shift 2
  quiet_parts="" sim_depth="" sim_traces="" sim_seed="" script=""
  cfg=$work/twin-$twin.cfg
  cp "$here/$spec.cfg" "$cfg"
  with_constants "$cfg" "Twin=\"$twin\"" "$@"
  replace_invariants "$cfg" "    $invariant"
  check "twin-$twin" "$cfg" "$invariant"
}

# The whole body is parsed before it runs, so editing this file never reaches a run in progress.
main() {
  [ $# -ge 2 ] || usage
  mode=$1
  spec=$2
  shift 2
  case $spec in EvsCommit|StoreSettle|IndexRollup) ;; *) usage ;; esac
  if [ "$mode" = list ]; then
    "twins_$spec"
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
      cfg=$work/live.cfg
      cp "$here/$spec.cfg" "$cfg"
      with_constants "$cfg" "$@"
      replace_invariants "$cfg" ""
      props=properties_$spec
      {
        grep -v '^SPECIFICATION\|^SYMMETRY\|^VIEW' "$cfg"
        echo "SPECIFICATION LiveSpec"
        echo "PROPERTY"
        for prop in ${!props}; do echo "    $prop"; done
      } > "$cfg.next" && mv "$cfg.next" "$cfg"
      check live "$cfg" pass || failed=1
      ;;
    twin|control)
      [ $# -ge 1 ] || usage
      want=$1
      shift
      line=$("twins_$spec" | awk -v t="$want" '$1 == t')
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
    stories)
      [ "$spec" = EvsCommit ] || usage
      while read -r story bounds; do
        quiet_parts="" sim_depth="" sim_traces="" sim_seed="" script=""
        cfg=$work/story-$story.cfg
        cp "$here/$spec.cfg" "$cfg"
        # shellcheck disable=SC2086
        with_constants "$cfg" $bounds "$@"
        check "story-$story" "$cfg" pass || failed=1
      done < <(stories_EvsCommit)
      ;;
    twins)
      while read -r twin invariant bounds; do
        # shellcheck disable=SC2086
        run_twin "$twin" "$invariant" $bounds "$@" || failed=1
      done < <("twins_$spec")
      ;;
    *)
      usage
      ;;
  esac
  return $failed
}

main "$@"; exit $?
