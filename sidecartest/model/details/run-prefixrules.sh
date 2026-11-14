#!/usr/bin/env bash
# Runs PrefixRules.tla, DESIGN-DETAILS.md section 16's client-checked prefix write rules, through the owner's TLC
# (ROOT/.stack/tools/tlc). A design configuration must pass; a twin breaks one rule of the design and must end
# with its one invariant violated; a reach configuration is the design with an invariant that says a state is
# never reached, and must end the same way. Prints one verdict line per run with the states, depth and time TLC
# reported, which section 16.3 records. Every run is breadth-first over the whole state graph at its bounds. The
# wrapper keeps TLC's state files out of the worktree and removes them when the run ends. The host is shared, so
# a design run takes four workers unless TLC_WORKERS says otherwise. A twin or a reach run takes one, so that the
# trace it stops at is a shortest one and the same on every run.
#
#   run-prefixrules.sh <track> [all | design | twins | reach | <Config>]...
#
# exit: 0 every run did what it must; 1 one did not; 64 usage
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
ROOT=/Users/builder/urnetwork-sidecar
[ $# -ge 1 ] || { echo "usage: run-prefixrules.sh <track> [all | design | twins | reach | <Config>]..." >&2; exit 64; }
track=$1
shift
designs="PrefixRules PrefixRules-Deep PrefixRules-Long"
twins="PrefixRulesTwin-NoCheck PrefixRulesTwin-NewestOnly PrefixRulesTwin-JudgeAtTip PrefixRulesTwin-HeadAtoms PrefixRulesTwin-DiffOnNewest PrefixRulesTwin-NoHeadFence PrefixRulesTwin-NoNewRefFence PrefixRulesTwin-RepairSkipsNames"
reaches="PrefixRulesReach-Ignored PrefixRulesReach-WalkedBack PrefixRulesReach-StalePin PrefixRulesReach-Hidden PrefixRulesReach-Repaired PrefixRulesReach-Tightened"
[ $# -ge 1 ] || set -- all
configs=
for name in "$@"; do
  case $name in
    all) configs="$configs $designs $twins $reaches" ;;
    design) configs="$configs $designs" ;;
    twins) configs="$configs $twins" ;;
    reach) configs="$configs $reaches" ;;
    *) configs="$configs $name" ;;
  esac
done
set -- $configs
failed=0
mkdir -p "$ROOT/.stack/scratch/$track"
for config in "$@"; do
  case $config in
    PrefixRules*) spec=PrefixRules.tla ;;
    *) echo "== FAIL $config: PrefixRules.tla has no such configuration"; failed=1; continue ;;
  esac
  [ -f "$here/$config.cfg" ] || { echo "== FAIL $config: no such configuration"; failed=1; continue; }
  case $config in
    *Twin-*|*Reach-*) workers=1 ;;
    *) workers=${TLC_WORKERS:-4} ;;
  esac
  out=$(mktemp "$ROOT/.stack/scratch/$track/prefixrules.XXXXXX")
  (cd "$here" && "$ROOT/.stack/tools/tlc" "$track" -config "$config.cfg" -workers "$workers" ${TLC_FLAGS:-} "$spec") > "$out" 2>&1
  code=$?
  rev=$(sed -n 's/.*(rev: \([0-9a-f]*\)).*/\1/p' "$out" | head -1)
  violated=$(sed -n -e 's/^Error: Invariant \(.*\) is violated.*/\1/p' -e 's/^Error: Temporal property \(.*\) was violated.*/\1/p' "$out" | head -1)
  distinct=$(sed -n 's/.* \([0-9,]*\) distinct states found.*/\1/p' "$out" | tail -1)
  depth=$(sed -n 's/^The depth of the complete state graph search is \([0-9]*\).*/\1/p' "$out" | tail -1)
  took=$(sed -n 's/^Finished in \(.*\) at .*/\1/p' "$out" | tail -1)
  trace=$(grep -c '^State [0-9]*:' "$out")
  expect=$(sed -n 's/^    \([A-Za-z]*\)$/\1/p' "$here/$config.cfg" | tail -1)
  facts="tlc $rev, exit $code, ${distinct:-?} distinct states, depth ${depth:-?}, ${took:-?}"
  case $config in
    *Twin-*|*Reach-*)
      if [ "$code" -ne 0 ] && [ "$violated" = "$expect" ]; then
        echo "== PASS $config: $expect violated as it must, a trace of $trace states, $facts"
      else
        echo "== FAIL $config: expected $expect violated, got ${violated:-no violation}, $facts"; failed=1
        grep -v '^Parsing\|^Semantic' "$out" | tail -40
      fi ;;
    *)
      if [ "$code" -eq 0 ]; then
        echo "== PASS $config: every invariant holds, $facts"
      else
        echo "== FAIL $config: ${violated:-a property, or no invariant named,} violated, $facts"; failed=1
        grep -v '^Parsing\|^Semantic' "$out" | tail -60
      fi ;;
  esac
  rm -f "$out"
done
exit $failed
