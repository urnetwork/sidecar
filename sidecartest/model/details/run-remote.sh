#!/usr/bin/env bash
# Runs DESIGN-DETAILS.md section 7's models through the owner's TLC (ROOT/.stack/tools/tlc): IndexSync.tla,
# RemoteAsk.tla, RemoteCursor.tla and RemoteMerge.tla. A design configuration (<Model>.cfg, <Model>-*.cfg)
# must pass. A configuration named <Model>Twin-* breaks one rule of the design and must end with the one
# invariant its cfg names violated. Prints one verdict line per run with the states, depth and time TLC
# reported and the most its state directory held, sampled every 2 s, which section 7.3 records. Every run is
# breadth-first over the whole state graph at its bounds; the *-Live configurations also check a temporal
# property under their LiveSpec's fairness. The wrapper keeps TLC's state files out of the worktree and
# removes them when the run ends; a run past TLC_TIME_CAP_S (1,800 s) or TLC_DISK_CAP_MB (4,096 MB) is
# stopped and reported as FAIL (bounded).
#
#   run-remote.sh <track> [all | design | twins | <Config>...]
#
# exit: 0 every run did what it must; 1 one did not; 64 usage
set -uo pipefail
main() {
  here=$(cd "$(dirname "$0")" && pwd)
  ROOT=/Users/builder/urnetwork-sidecar
  [ $# -ge 1 ] || { echo "usage: run-remote.sh <track> [all | design | twins | <Config>...]" >&2; exit 64; }
  track=$1
  shift
  cap=${TLC_DISK_CAP_MB:-4096}
  timecap=${TLC_TIME_CAP_S:-1800}
  models="IndexSync RemoteAsk RemoteCursor RemoteMerge"
  names() { (cd "$here" && ls $1 2>/dev/null | sed 's/\.cfg$//' | tr '\n' ' '); }
  designs=""
  twins=""
  for model in $models; do
    designs="$designs $(names "$model.cfg") $(names "$model-*.cfg")"
    twins="$twins $(names "${model}Twin-*.cfg")"
  done
  case "${1:-all}" in
    all) set -- $designs $twins ;;
    design) set -- $designs ;;
    twins) set -- $twins ;;
  esac
  run=$track.remote.$$
  failed=0
  for config in "$@"; do
    model=${config%%-*}
    model=${model%Twin}
    out=$(mktemp "${TMPDIR:-/tmp}/remote.XXXXXX")
    peak=$(mktemp "${TMPDIR:-/tmp}/remote.XXXXXX")
    echo 0 > "$peak"
    (cd "$here" && "$ROOT/.stack/tools/tlc" "$run" -config "$config.cfg" -workers "${TLC_WORKERS:-auto}" ${TLC_FLAGS:-} "$model.tla") > "$out" 2>&1 &
    runner=$!
    began=$(date +%s)
    bounded=
    while kill -0 "$runner" 2>/dev/null; do
      sleep 2
      held=$(du -sm "$ROOT/.stack/scratch/$run.tlc."* 2>/dev/null | awk '{s += $1} END {print s + 0}')
      [ "$held" -gt "$(cat "$peak")" ] && echo "$held" > "$peak"
      if [ "$held" -gt "$cap" ] || [ $(( $(date +%s) - began )) -gt "$timecap" ]; then
        bounded=1
        pkill -TERM -P "$runner" 2>/dev/null
        kill -TERM "$runner" 2>/dev/null
        sleep 2
        pkill -KILL -f "$run.tlc" 2>/dev/null
      fi
    done
    wait "$runner"
    code=$?
    rm -rf "$ROOT/.stack/scratch/$run.tlc."* 2>/dev/null
    rev=$(sed -n 's/.*(rev: \([0-9a-f]*\)).*/\1/p' "$out" | head -1)
    violated=$(sed -n -e 's/^Error: Invariant \(.*\) is violated.*/\1/p' -e 's/^Error: Temporal property \(.*\) was violated.*/\1/p' "$out" | head -1)
    distinct=$(sed -n 's/.* \([0-9,]*\) distinct states found.*/\1/p' "$out" | tail -1)
    depth=$(sed -n 's/^The depth of the complete state graph search is \([0-9]*\).*/\1/p' "$out" | tail -1)
    took=$(sed -n 's/^Finished in \(.*\) at .*/\1/p' "$out" | tail -1)
    trace=$(grep -c '^State [0-9]*:' "$out")
    expect=$(sed -n 's/^    \([A-Za-z]*\)$/\1/p' "$here/$config.cfg" | tail -1)
    facts="tlc $rev, exit $code, ${distinct:-?} distinct states, depth ${depth:-?}, ${took:-?}, at most $(cat "$peak") MB on disk"
    if [ -n "$bounded" ]; then
      echo "== FAIL (bounded) $config: stopped at its disk or time cap, $facts"; failed=1
    else
      case $config in
        *Twin-*)
          if [ "$code" -ne 0 ] && [ "$violated" = "$expect" ]; then
            echo "== PASS $config: $expect violated as it must, a trace of $trace states, $facts"
          else
            echo "== FAIL $config: expected $expect violated, got ${violated:-no violation}, $facts"; failed=1
            grep -v '^Parsing\|^Semantic' "$out" | tail -40
          fi ;;
        *)
          if [ "$code" -eq 0 ]; then
            echo "== PASS $config: every invariant and property holds, $facts"
          else
            echo "== FAIL $config: ${violated:-a property, or no invariant named,} violated, $facts"; failed=1
            grep -v '^Parsing\|^Semantic' "$out" | tail -60
          fi ;;
      esac
    fi
    [ -n "${TLC_KEEP_OUT:-}" ] && cp "$out" "$TLC_KEEP_OUT/$config.out"
    rm -f "$out" "$peak"
  done
  exit $failed
}
main "$@"
