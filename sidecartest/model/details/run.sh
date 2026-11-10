#!/usr/bin/env bash
# Runs AuthLog.tla's configurations through the owner's TLC (ROOT/.stack/tools/tlc): the design at its
# bounds, which must pass, and each twin, which must end with its one invariant violated. Prints one
# verdict line per run with the states, depth and time TLC reported, which DESIGN-DETAILS.md section
# 5.3 records.
#
#   run.sh <track> [all | design | twins | <Config>...]
#
# AuthLog-Narrow, one entry deeper than the other design runs, runs by TLC's random simulation rather than
# breadth-first search, since its complete state graph passes 20 million states: 200,000 traces of up to 7
# steps from seed 1, which shows those behaviors kept every invariant and no more, and took 1 h 46 min on
# 14 cores on 2026-11-09. TLC_FLAGS adds flags to any run, as in TLC_FLAGS="-simulate num=1000 -depth 7
# -seed 1" for a shorter simulation.
#
# exit: 0 every run did what it must; 1 one did not; 64 usage
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
ROOT=/Users/builder/urnetwork-sidecar
[ $# -ge 1 ] || { echo "usage: run.sh <track> [all | design | twins | <Config>...]" >&2; exit 64; }
track=$1
shift
designs="AuthLog AuthLog-K1 AuthLog-Adversary AuthLog-Narrow"
twins="Twin-JudgeTail-Head Twin-JudgeTail-At Twin-NoProposalRows Twin-NoSettingsRows Twin-NoRingRows Twin-ReJudgeTail Twin-CascadeFromAt Twin-NoBitsCheck Twin-NoBitsCheck-Forks Twin-CloseAtBase Twin-NoTailCap Twin-NewestConfirmOnly Twin-DelegationEndIgnored"
case "${1:-all}" in
  all) set -- $designs $twins ;;
  design) set -- $designs ;;
  twins) set -- $twins ;;
esac
failed=0
for config in "$@"; do
  out=$(mktemp "${TMPDIR:-/tmp}/authlog.XXXXXX")
  flags=${TLC_FLAGS:-}
  if [ "$config" = AuthLog-Narrow ] && [ -z "$flags" ]; then
    flags="-simulate num=200000 -depth 7 -seed 1"
  fi
  (cd "$here" && "$ROOT/.stack/tools/tlc" "$track" -config "$config.cfg" -workers "${TLC_WORKERS:-auto}" $flags AuthLog.tla) > "$out" 2>&1
  code=$?
  rev=$(sed -n 's/.*(rev: \([0-9a-f]*\)).*/\1/p' "$out" | head -1)
  violated=$(sed -n 's/^Error: Invariant \(.*\) is violated.*/\1/p' "$out" | head -1)
  distinct=$(sed -n 's/.* \([0-9,]*\) distinct states found.*/\1/p' "$out" | tail -1)
  depth=$(sed -n 's/^The depth of the complete state graph search is \([0-9]*\).*/\1/p' "$out" | tail -1)
  took=$(sed -n 's/^Finished in \(.*\) at .*/\1/p' "$out" | tail -1)
  trace=$(grep -c '^State [0-9]*:' "$out")
  expect=$(sed -n 's/^    \([A-Za-z]*\)$/\1/p' "$config.cfg" | tail -1)
  generated=$(sed -n 's/^The number of states generated: \([0-9,]*\).*/\1/p' "$out" | tail -1)
  if [ -n "$generated" ]; then
    facts="tlc $rev, exit $code, simulation, $generated states generated, ${took:-?}"
  else
    facts="tlc $rev, exit $code, ${distinct:-?} distinct states, depth ${depth:-?}, ${took:-?}"
  fi
  case $config in
    Twin-*)
      if [ "$code" -ne 0 ] && [ "$violated" = "$expect" ]; then
        echo "== PASS $config: $expect violated as it must, a trace of $trace states, $facts"
      else
        echo "== FAIL $config: expected $expect violated, got ${violated:-no violation}, $facts"; failed=1
        grep -v '^Parsing\|^Semantic' "$out" | tail -40
      fi ;;
    *)
      if [ "$code" -eq 0 ]; then
        echo "== PASS $config: $facts"
      else
        echo "== FAIL $config: ${violated:-error}, $facts"; failed=1
        grep -v '^Parsing\|^Semantic' "$out" | tail -60
      fi ;;
  esac
  rm -f "$out"
done
exit $failed
