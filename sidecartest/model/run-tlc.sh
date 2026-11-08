#!/usr/bin/env bash
# Runs §22.8's model checks (D-TEST-10) with TLC: a model at its .cfg's bounds, which must pass;
# each twin, which breaks one rule of the design and must make TLC report the invariant that rule
# protects; and the liveness properties under weak fairness.
#
#   run-tlc.sh model <Spec> [Name=value ...]          the model, at its cfg's bounds or these
#   run-tlc.sh twins <Spec> [Name=value ...]          every twin of the model, in turn
#   run-tlc.sh twin <Spec> <Twin> [Name=value ...]    one twin
#   run-tlc.sh live <Spec> [Name=value ...]           the liveness properties, without symmetry or view
#   run-tlc.sh list <Spec>                            the twins and the invariant each must break
#
# <Spec> is EvsCommit or StoreSettle. TLC names a command that runs tlc2.TLC, as in
#   TLC="java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC" run-tlc.sh model StoreSettle
# and TLC_FLAGS adds flags, as in TLC_FLAGS="-workers 8". Each run works in a fresh directory under
# TMPDIR, so no state or trace file lands beside the specs. TLC prints its revision first: name it
# with any result.
#
# exit: 0 every run did what it must; 1 one did not; 64 usage
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)

usage() {
  sed -n '6,10p' "$0" | sed 's/^# //' >&2
  exit 64
}

# Each twin, the invariant it must break, and the bounds it runs at in place of the cfg's, small
# enough that breadth-first search reaches the violation; a twin's run checks only its invariant.
twins_EvsCommit() {
  cat <<'EOF'
StaleHorizon           FileCas
UnrecordedRefusal      OutcomesHold
CachedRefusal          OutcomesHold
AnswerDeletes          AnswersDeleteNothing
GcNoFence              GcSafe
GcNoSecondCheck        GcSafe
EvacuateBeforeIndex    ClosureHolds
PageOutUnfolded        NewestFound
NoWindowWait           NewestFound
FoldIgnoresWindow      NewestFound
VersionRestarts        VersionsRise
NoPinCheck             PinsHold
PinFalls               PinsHold
LadderFork             OneLadder
RestoreAfterShred      LifecycleHolds
GitPathCas             GitTip
NoFenceRule            OutcomesHold
NoIfMatchFold          NewestFound
NoTailCheck            NewestFound
EarlyRefusalDrop       OutcomesHold
CopyOverwrites         NewestFound
NoRetryLookup          OutcomesHold
ResolveIgnoresPending  OutcomesHold
EOF
}

twins_StoreSettle() {
  cat <<'EOF'
ReleaseOnCancel        NoStaleQuorum
NoDeadlineCheck        LateWritesNeverRead
NoVersionCheck         NoStaleQuorum
RevertBelowQuorumOnly  LateWritesNeverRead
SettlerRevertsUnseen   NoStaleQuorum
HealMinority           NoStaleQuorum
NoDriveLock            NoStaleQuorum
AbsentCountsForDelete  NoStaleQuorum
EOF
}

properties_EvsCommit="RemovalGates DueEpochCommits"
properties_StoreSettle="HeldKeyReleased"

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

# The cfg with each Name=value replacing that constant's line; an unknown name is refused.
with_constants() {
  local cfg=$1 pair name value
  shift
  for pair in "$@"; do
    name=${pair%%=*}
    value=${pair#*=}
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

# One TLC run; prints its output and a summary line, and says whether it ended as expected: a pass,
# or the named invariant violated.
check() {
  local label=$1 cfg=$2 expect=$3 out=$work/$1.out code violated distinct depth took
  echo "== $label: $(grep -v '^\\\*' "$cfg" | tr '\n' ' ' | sed 's/  */ /g')"
  # shellcheck disable=SC2086
  (cd "$work" && $TLC ${TLC_FLAGS:-} -config "$cfg" "$spec.tla") 2>&1 | tee "$out"
  code=${PIPESTATUS[0]}
  violated=$(sed -n 's/^Error: Invariant \(.*\) is violated.*/\1/p' "$out" | head -1)
  distinct=$(sed -n 's/.* \([0-9,]*\) distinct states found.*/\1/p' "$out" | tail -1)
  depth=$(sed -n 's/^The depth of the complete state graph search is \([0-9]*\).*/\1/p' "$out" | tail -1)
  took=$(sed -n 's/^Finished in \(.*\) at .*/\1/p' "$out" | tail -1)
  local facts="exit $code, ${distinct:-?} distinct states, depth ${depth:-?}, ${took:-?}"
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
  cfg=$work/twin-$twin.cfg
  cp "$here/$spec.cfg" "$cfg"
  with_constants "$cfg" "Twin=\"$twin\"" "$@"
  replace_invariants "$cfg" "    $invariant"
  check "twin-$twin" "$cfg" "$invariant"
}

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
  twin)
    [ $# -ge 1 ] || usage
    want=$1
    shift
    line=$("twins_$spec" | awk -v t="$want" '$1 == t')
    [ -n "$line" ] || { echo "run-tlc.sh: $spec has no twin $want" >&2; exit 64; }
    read -r _ invariant bounds <<< "$line"
    # shellcheck disable=SC2086
    run_twin "$want" "$invariant" $bounds "$@" || failed=1
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
exit $failed
