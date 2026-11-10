#!/usr/bin/env bash
# Runs DESIGN-DETAILS.md section 9's model, PathEpoch.tla, through the owner's TLC (ROOT/.stack/tools/tlc). A
# design config must pass. A config named *Twin-* breaks one rule of the design and a config named *Reach-* denies
# a state the design must reach, and each of those must end with the one invariant its cfg names last violated.
# Prints one verdict line per run with the states, depth and time TLC reported and the most its state directory
# held, sampled every 5 s, which section 9.3 records.
#
#   run-pathepoch.sh <track> [all | design | twins | reach | <Config>...]
#
# Disk: the disk is shared with four build lanes, so every run is bounded on disk as well as in states. The
# breadth-first configs run at bounds whose complete graphs finish in minutes; PathEpoch-Wide runs by TLC's
# random simulation (a fixed number of traces of a fixed depth from a fixed seed), which keeps no state set on
# disk and shows only that the behaviors it drew kept every invariant. Whatever the mode, a run whose state
# directory passes TLC_DISK_CAP_MB (8,192 MB) is stopped and reported as FAIL (bounded), and every run's state
# directory is deleted when it ends. Each invocation names its own state directories, so two may run at once.
# TLC_FLAGS adds flags to any run, TLC_WORKERS sets its workers and TLC_HEAP its heap.
#
# exit: 0 every run did what it must; 1 one did not; 64 usage
set -uo pipefail
# The whole body is parsed before it runs, so editing this file never reaches a run in progress.
main() {
  here=$(cd "$(dirname "$0")" && pwd)
  ROOT=/Users/builder/urnetwork-sidecar
  [ $# -ge 1 ] || { echo "usage: run-pathepoch.sh <track> [all | design | twins | reach | <Config>...]" >&2; exit 64; }
  track=$1
  shift
  cap=${TLC_DISK_CAP_MB:-8192}
  designs="PathEpoch PathEpoch-Mappers PathEpoch-Three PathEpoch-Two PathEpoch-Pair PathEpoch-NewRef PathEpoch-Wide"
  twins="PathEpochTwin-NoBetweenFence PathEpochTwin-NoTailCheck PathEpochTwin-FoldKeepsSources PathEpochTwin-BlindRetoken PathEpochTwin-MissIsAbsent PathEpochTwin-SendAllSources PathEpochTwin-MapAllSources PathEpochTwin-StaleEpochSend PathEpochTwin-NoNewNameRule PathEpochTwin-RowsBeforeMoves PathEpochTwin-RemoveCurrentRowOnly PathEpochTwin-NewRefAtOne PathEpochTwin-StaleFirstPush"
  reach="PathEpochReach-TwoCutOvers PathEpochReach-Retoken PathEpochReach-NewRefLate"
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
    [ -f "$here/$config.cfg" ] || { echo "run-pathepoch.sh: no config $config" >&2; exit 64; }
    out=$(mktemp "${TMPDIR:-/tmp}/pathepoch.XXXXXX")
    flags=${TLC_FLAGS:-}
    if [ -z "$flags" ]; then
      case $config in
        PathEpoch-Wide) flags="-simulate num=100000 -depth 80 -seed 9" ;;
      esac
    fi
    (cd "$here" && exec "$ROOT/.stack/tools/tlc" "$run" -config "$config.cfg" -workers "${TLC_WORKERS:-auto}" $flags PathEpoch.tla) > "$out" 2>&1 &
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
    generated=$(sed -n 's/^The number of states generated: \([0-9,]*\).*/\1/p' "$out" | tail -1)
    if [ -n "$generated" ]; then
      facts="tlc $rev, exit $code, simulation, $generated states generated, ${took:-?}"
    else
      facts="tlc $rev, exit $code, ${distinct:-?} distinct states, depth ${depth:-?}, ${took:-?}"
    fi
    facts="$facts, $peak MB on disk at most"
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
