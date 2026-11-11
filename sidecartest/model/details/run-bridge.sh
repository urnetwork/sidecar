#!/usr/bin/env bash
# Runs section 12's three models through the owner's TLC (ROOT/.stack/tools/tlc): BridgeNat.tla (the bridge
# engine against the host's NAT), ShareSign.tla (a share's signers against removal and revocation) and
# BridgeFold.tla (one body-level verdict at every reader, whatever base it started from). A design
# configuration must pass; a twin must end with its one invariant violated; a reach configuration is the
# design with an invariant it does not hold, and must end the same way. Prints one verdict line per run with
# the states, depth and time TLC reported, which DESIGN-DETAILS.md section 12.3 records. Every run is
# breadth-first over the whole state graph at its bounds. The wrapper keeps TLC's state files out of the
# worktree and removes them when the run ends. The host is shared, so the default is four workers.
#
#   run-bridge.sh <track> [all | design | twins | reach | <Config>...]
#
# exit: 0 every run did what it must; 1 one did not; 64 usage
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
ROOT=/Users/builder/urnetwork-sidecar
[ $# -ge 1 ] || { echo "usage: run-bridge.sh <track> [all | design | twins | reach | <Config>...]" >&2; exit 64; }
track=$1
shift
designs="BridgeNat BridgeNat-Forwarder BridgeNat-TwoRules BridgeNat-Long ShareSign ShareSign-Wide BridgeFold"
twins="BridgeNatTwin-CloseBeforePublish BridgeNatTwin-NoRecheck BridgeNatTwin-StateDropsOverlay BridgeNatTwin-LowerStateAccepted BridgeNatTwin-RevokeAtZero BridgeNatTwin-ProviderBeforeCatchUp BridgeNatTwin-ProviderBeforeHook ShareSignTwin-NoWriteGate ShareSignTwin-SeedReuse ShareSignTwin-NoRatchet ShareSignTwin-RatchetVolatile ShareSignTwin-LongCert ShareSignTwin-RevokeKeepsKey BridgeFoldTwin-KeepOwnVerdict BridgeFoldTwin-NewDeviceVoid BridgeFoldTwin-NoLedger BridgeFoldTwin-FreezeNewPolicy"
reaches="BridgeNatReach-Opens ShareSignReach-Member ShareSignReach-RemovedInBound ShareSignReach-HolderRemoved BridgeFoldReach-Turn"
case "${1:-all}" in
  all) set -- $designs $twins $reaches ;;
  design) set -- $designs ;;
  twins) set -- $twins ;;
  reach) set -- $reaches ;;
esac
failed=0
for config in "$@"; do
  case $config in
    BridgeNat*) spec=BridgeNat.tla ;;
    ShareSign*) spec=ShareSign.tla ;;
    BridgeFold*) spec=BridgeFold.tla ;;
    *) echo "== FAIL $config: no model of section 12 has that configuration"; failed=1; continue ;;
  esac
  out=$(mktemp "${TMPDIR:-/tmp}/bridge.XXXXXX")
  (cd "$here" && "$ROOT/.stack/tools/tlc" "$track" -config "$config.cfg" -workers "${TLC_WORKERS:-4}" ${TLC_FLAGS:-} "$spec") > "$out" 2>&1
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
