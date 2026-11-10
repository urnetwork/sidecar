#!/usr/bin/env bash
# Runs Fwd.tla's configurations through the owner's TLC (ROOT/.stack/tools/tlc): the design at its bounds,
# which must pass, and each twin, which must end with its one invariant violated. Prints one verdict line
# per run with the states, depth and time TLC reported, which DESIGN-DETAILS.md section 4.3 records. Every
# run is breadth-first over the whole state graph at its bounds and finishes in minutes; the wrapper keeps
# TLC's state files out of the worktree and removes them when the run ends.
#
#   run-fwd.sh <track> [all | design | twins | <Config>...]
#
# exit: 0 every run did what it must; 1 one did not; 64 usage
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
ROOT=/Users/builder/urnetwork-sidecar
[ $# -ge 1 ] || { echo "usage: run-fwd.sh <track> [all | design | twins | <Config>...]" >&2; exit 64; }
track=$1
shift
designs="Fwd Fwd-Rollback"
twins="FwdTwin-NoDelegationOverlay FwdTwin-OverlayLifts FwdTwin-OverlayOpens FwdTwin-StateDropsOverlay FwdTwin-LowerStateAccepted FwdTwin-NoFloor FwdTwin-NoOverdue"
case "${1:-all}" in
  all) set -- $designs $twins ;;
  design) set -- $designs ;;
  twins) set -- $twins ;;
esac
failed=0
for config in "$@"; do
  out=$(mktemp "${TMPDIR:-/tmp}/fwd.XXXXXX")
  (cd "$here" && "$ROOT/.stack/tools/tlc" "$track" -config "$config.cfg" -workers "${TLC_WORKERS:-auto}" ${TLC_FLAGS:-} Fwd.tla) > "$out" 2>&1
  code=$?
  rev=$(sed -n 's/.*(rev: \([0-9a-f]*\)).*/\1/p' "$out" | head -1)
  violated=$(sed -n 's/^Error: Invariant \(.*\) is violated.*/\1/p' "$out" | head -1)
  distinct=$(sed -n 's/.* \([0-9,]*\) distinct states found.*/\1/p' "$out" | tail -1)
  depth=$(sed -n 's/^The depth of the complete state graph search is \([0-9]*\).*/\1/p' "$out" | tail -1)
  took=$(sed -n 's/^Finished in \(.*\) at .*/\1/p' "$out" | tail -1)
  trace=$(grep -c '^State [0-9]*:' "$out")
  expect=$(sed -n 's/^    \([A-Za-z]*\)$/\1/p' "$config.cfg" | tail -1)
  facts="tlc $rev, exit $code, ${distinct:-?} distinct states, depth ${depth:-?}, ${took:-?}"
  case $config in
    FwdTwin-*)
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
        echo "== FAIL $config: ${violated:-no invariant named} violated, $facts"; failed=1
        grep -v '^Parsing\|^Semantic' "$out" | tail -60
      fi ;;
  esac
  rm -f "$out"
done
exit $failed
