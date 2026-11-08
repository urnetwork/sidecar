#!/usr/bin/env bash
# Runs §22.8's model checks (D-TEST-10) with TLC: a model at its .cfg's bounds, which must pass;
# each twin, which breaks one rule of the design and must make TLC report the invariant that rule
# protects; and the liveness properties under weak fairness.
#
#   run-tlc.sh model <Spec> [Name=value ...]          the model, at its cfg's bounds or these
#   run-tlc.sh twins <Spec> [Name=value ...]          every twin of the model, in turn
#   run-tlc.sh twin <Spec> <Twin> [Name=value ...]    one twin
#   run-tlc.sh control <Spec> <Twin> [Name=value ...] the model at that twin's bounds, which must pass
#   run-tlc.sh live <Spec> [Name=value ...]           the liveness properties, without symmetry or view
#   run-tlc.sh list <Spec>                            the twins and the invariant each must break
#
# <Spec> is EvsCommit or StoreSettle. A Name=value replaces a constant of the spec's cfg, and
# Quiet=a+b leaves the named processes out (quiet_EvsCommit below). TLC names a command that runs
# tlc2.TLC, as in
#   TLC="java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC" run-tlc.sh model StoreSettle
# and TLC_FLAGS adds flags, as in TLC_FLAGS="-workers 8". Each run works in a fresh directory under
# TMPDIR, so no state or trace file lands beside the specs. TLC prints its revision first: name it
# with any result.
#
# exit: 0 every run did what it must; 1 one did not; 64 usage
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)

usage() {
  sed -n '6,11p' "$0" | sed 's/^# //' >&2
  exit 64
}

# Each twin, the invariant it must break, and the bounds it runs at in place of the cfg's, small
# enough that breadth-first search reaches the violation; a twin's run checks only its invariant.
# seq is one writer and one instance, each push answered before the next; tiny is a window of 2
# versions paging out one at a time, so a page-out fits in a short behavior; quiet_but holds still
# every part a twin's rule never reaches; sim is random simulation, for the twins whose violations
# lie past 30 steps. Two of the model's twins have no row, since no invariant can see them: NoTailCheck,
# as the model carries nothing a tail holds (a new epoch's tokens for paths created after the map's
# source), and NoFenceRule, as at the model's hour marks every attempt a fence ends has lapsed (5b)
# or holds a receipt or map too old to pass (5h, 5e) by then.
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
  local seq=$seq_EvsCommit tiny=$tiny_EvsCommit sim="Simulate=200 Traces=3000000 Seed=1"
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
ResolveIgnoresPending  OutcomesHold          $seq MaxPush=1 MaxHour=3 $(quiet_but evac)+gitref
GcNoFence              GcSafe                $seq MaxPush=1 MaxHour=3 MaxFaults=1 $(quiet_but gc uploads)+gitref
GcNoSecondCheck        GcSafe                $seq MaxPush=1 MaxHour=3 MaxFaults=1 $(quiet_but gc uploads)+gitref
PageOutUnfolded        NewestFound           $seq MaxPush=3 $tiny $(quiet_but)+gitref
StaleHorizon           FileCas               $seq Writers={w1,w2} Instances={i1,i2} MaxPush=3 $(quiet_but fold)+gitref $sim
NoIfMatchFold          NewestFound           $seq Instances={i1,i2} MaxPush=3 $(quiet_but fold)+gitref $sim
NoRetryLookup          OutcomesHold          $seq Writers={w1,w2} Instances={i1,i2} MaxPush=3 $tiny $(quiet_but fold)+gitref $sim
NoWindowWait           NewestFound           $seq MaxPush=6 MaxVersion=7 $tiny $(quiet_but fold collect)+gitref $sim
FoldIgnoresWindow      NewestFound           $seq MaxPush=6 MaxVersion=7 $tiny $(quiet_but fold collect)+gitref $sim
CachedRefusal          OutcomesHold          $seq Writers={w1,w2,w3} MaxAttempts=2 MaxGeneration=2 MaxPush=5 MaxVersion=6 $(quiet_but authority epoch cache stale)+gitref $sim
CopyOverwrites         NewestFound           $seq Writers={w1,w2,w3} MaxGeneration=2 MaxPush=5 MaxVersion=6 $(quiet_but authority epoch fold)+gitref $sim
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

properties_EvsCommit="RemovalGates DueEpochCommits"
properties_StoreSettle="HeldKeyReleased"

# Quiet=a+b leaves processes out of a run: a module extending the spec holds each named part still
# by an action constraint, so the spec stays the design's. A run with any part quiet covers less, and
# its report must say which.
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
EOF
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
# place of breadth-first search, at most Traces=<n> behaviors from Seed=<s>: for a twin whose
# violation lies deeper than search reaches it finds a trace, and for a control it shows only that
# n random behaviors kept every invariant.
quiet_parts="" sim_depth="" sim_traces="" sim_seed=""
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
  local cfg=$1 part conj body=""
  module=$spec
  [ -n "$quiet_parts" ] || return 0
  for part in ${quiet_parts//+/ }; do
    conj=$("quiet_$spec" | awk -v p="$part" '$1 == p { $1 = ""; sub(/^ +/, ""); print }')
    [ -n "$conj" ] || { echo "run-tlc.sh: $spec has no quiet part $part" >&2; exit 64; }
    body="$body    /\\ $conj"$'\n'
  done
  printf -- '---- MODULE MC ----\nEXTENDS %s\nQuiet ==\n%s====\n' "$spec" "$body" > "$work/MC.tla"
  echo "ACTION_CONSTRAINT Quiet" >> "$cfg"
  module=MC
}

# One TLC run; prints its output and a summary line, and says whether it ended as expected: a pass,
# or the named invariant violated.
check() {
  local label=$1 cfg=$2 expect=$3 out=$work/$1.out code violated distinct depth took search="" facts
  quieten "$cfg"
  if [ -n "$sim_depth" ]; then
    search="-simulate num=${sim_traces:-10000000} -depth $sim_depth -seed ${sim_seed:-1}"
  fi
  echo "== $label: $(grep -v '^\\\*' "$cfg" | tr '\n' ' ' | sed 's/  */ /g')${quiet_parts:+ Quiet $quiet_parts}${search:+ $search}"
  # shellcheck disable=SC2086
  (cd "$work" && $TLC ${TLC_FLAGS:-} $search -config "$cfg" "$module.tla") 2>&1 | tee "$out"
  code=${PIPESTATUS[0]}
  violated=$(sed -n 's/^Error: Invariant \(.*\) is violated.*/\1/p' "$out" | head -1)
  took=$(sed -n 's/^Finished in \(.*\) at .*/\1/p' "$out" | tail -1)
  if [ -n "$search" ]; then
    facts="exit $code, simulation, $(sed -n 's/^The number of states generated: \([0-9,]*\).*/\1/p' "$out" | tail -1) states generated"
  else
    distinct=$(sed -n 's/.* \([0-9,]*\) distinct states found.*/\1/p' "$out" | tail -1)
    depth=$(sed -n 's/^The depth of the complete state graph search is \([0-9]*\).*/\1/p' "$out" | tail -1)
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
  quiet_parts="" sim_depth="" sim_traces="" sim_seed=""
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
  case $spec in EvsCommit|StoreSettle) ;; *) usage ;; esac
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
