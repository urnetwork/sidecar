#!/usr/bin/env bash
# Runs DESIGN-DETAILS.md section 17's model through the owner's TLC (ROOT/.stack/tools/tlc): CertOrder.tla, one
# customer ACME account's lock, its rows' recorded orders and the CA's orders, under several ordering desktops.
# A design config must pass. A config named *Twin-* breaks one rule of the design and a config named *Reach-*
# denies a state the design must reach, and each of those must end with the one invariant its cfg names last
# violated. Prints one verdict line per run with the states, depth and time TLC reported and the most its
# state directory held, sampled every 5 s, which section 17.3 records.
#
#   run-certorder.sh <track> [all | design | twins | reach | <Config>...]
#
# Disk: the disk is shared with the build lanes, so every run is bounded. Each is breadth-first over a whole
# state graph that finishes in minutes; a run whose state directory passes TLC_DISK_CAP_MB (5,120 MB) is
# stopped and reported as FAIL (bounded), and every run's state directory is deleted when it ends. Each
# invocation names its own state directories, so two may run at once. TLC_FLAGS adds flags to any run,
# TLC_WORKERS sets its workers and TLC_HEAP its heap.
#
# exit: 0 every run did what it must; 1 one did not; 64 usage
set -uo pipefail
# The whole body is parsed before it runs, so editing this file never reaches a run in progress.
main() {
  here=$(cd "$(dirname "$0")" && pwd)
  ROOT=/Users/builder/urnetwork-sidecar
  [ $# -ge 1 ] || { echo "usage: run-certorder.sh <track> [all | design | twins | reach | <Config>...]" >&2; exit 64; }
  track=$1
  shift
  cap=${TLC_DISK_CAP_MB:-5120}
  designs="CertOrder CertOrder-Long CertOrder-Three"
  twins="CertOrderTwin-NoRecord CertOrderTwin-NoResume CertOrderTwin-ReplaceLive CertOrderTwin-TwoInFlight CertOrderTwin-TwoInFlightBlind CertOrderTwin-FailKeepsOrder"
  reach="CertOrderReach-Resumed CertOrderReach-Reused CertOrderReach-Killed CertOrderReach-Reordered"
  case "${1:-all}" in
    all) set -- $designs $twins $reach ;;
    design) set -- $designs ;;
    twins) set -- $twins ;;
    reach) set -- $reach ;;
  esac
  # each invocation names its own state directories, so two at once never take each other's
  run=$track.$$
  metadirs() { ls -d "$ROOT/.stack/scratch/$run.tlc."* 2>/dev/null; }
  runner=
  # a stopped script stops its TLC and deletes the run's state directory, so a timeout never leaves a run going
  stop() {
    if [ -n "$runner" ]; then
      for pid in $(pgrep -P "$runner"); do kill -TERM "$pid" 2>/dev/null; done
      kill -TERM "$runner" 2>/dev/null
      sleep 2
      for pid in $(pgrep -P "$runner"); do kill -KILL "$pid" 2>/dev/null; done
    fi
    for dir in $(metadirs); do rm -rf "$dir"; done
  }
  trap 'stop; exit 1' TERM INT
  failed=0
  for config in "$@"; do
    [ -f "$here/$config.cfg" ] || { echo "run-certorder.sh: no config $config" >&2; exit 64; }
    case $config in
      CertOrder*) spec=CertOrder.tla ;;
      *) echo "run-certorder.sh: no model for $config" >&2; exit 64 ;;
    esac
    out=$(mktemp "${TMPDIR:-/tmp}/certorder.XXXXXX")
    (cd "$here" && exec "$ROOT/.stack/tools/tlc" "$run" -config "$config.cfg" -workers "${TLC_WORKERS:-auto}" ${TLC_FLAGS:-} "$spec") > "$out" 2>&1 &
    runner=$!
    bounded=0
    peak=0
    while kill -0 "$runner" 2>/dev/null; do
      sleep 5
      for dir in $(metadirs); do
        used=$(du -sm "$dir" 2>/dev/null | cut -f1)
        [ "${used:-0}" -gt "$peak" ] && peak=$used
        if [ "${used:-0}" -gt "$cap" ]; then
          bounded=1
          for pid in $(pgrep -P "$runner"); do kill -TERM "$pid" 2>/dev/null; done
          kill -TERM "$runner" 2>/dev/null
          sleep 3
          for pid in $(pgrep -P "$runner"); do kill -KILL "$pid" 2>/dev/null; done
        fi
      done
    done
    wait "$runner"
    code=$?
    runner=
    for dir in $(metadirs); do rm -rf "$dir"; done
    rev=$(sed -n 's/.*(rev: \([0-9a-f]*\)).*/\1/p' "$out" | head -1)
    violated=$(sed -n 's/^Error: Invariant \(.*\) is violated.*/\1/p' "$out" | head -1)
    distinct=$(sed -n 's/.* \([0-9,]*\) distinct states found.*/\1/p' "$out" | tail -1)
    depth=$(sed -n 's/^The depth of the complete state graph search is \([0-9]*\).*/\1/p' "$out" | tail -1)
    took=$(sed -n 's/^Finished in \(.*\) at .*/\1/p' "$out" | tail -1)
    trace=$(grep -c '^State [0-9]*:' "$out")
    # the last indented name of the cfg: the one invariant a twin or a reach config must break
    expect=$(sed -n 's/^    \([A-Za-z]*\)$/\1/p' "$here/$config.cfg" | tail -1)
    facts="tlc $rev, exit $code, ${distinct:-?} distinct states, depth ${depth:-?}, ${took:-?}, $peak MB on disk at most"
    if [ "$bounded" -eq 1 ]; then
      echo "== FAIL $config: stopped at the $cap MB disk cap, $facts"; failed=1
    else
      case $config in
        *Twin-*|*Reach-*)
          if [ "$code" -ne 0 ] && [ "$violated" = "$expect" ]; then
            echo "== PASS $config: $expect violated as it must, a trace of $trace states, $facts"
          else
            echo "== FAIL $config: expected $expect violated, got ${violated:-no violation}, $facts"; failed=1
            grep -v '^Parsing\|^Semantic\|^Linting' "$out" | tail -40
          fi ;;
        *)
          if [ "$code" -eq 0 ]; then
            echo "== PASS $config: $facts"
          else
            echo "== FAIL $config: ${violated:-error}, $facts"; failed=1
            grep -v '^Parsing\|^Semantic\|^Linting' "$out" | tail -60
          fi ;;
      esac
    fi
    [ -n "${TLC_KEEP_OUT:-}" ] && cp "$out" "$TLC_KEEP_OUT/$config.out"
    rm -f "$out"
  done
  return $failed
}

main "$@"; exit $?
