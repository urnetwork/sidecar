#!/usr/bin/env bash
# Runs DESIGN-DETAILS.md section 15's model through the owner's TLC (ROOT/.stack/tools/tlc): IndexErase.tla, an
# erasure on one index ref beside the writers that keep pushing, as two specifications: SpecPath, a path
# document whose edit may rest on the version a CUT lists, and SpecCard, a run card through an erasure. A
# design config must pass. A config named *Landed-* is section 1 as it stood on 2026-11-12, and one named
# *Twin-* breaks one rule of the design, and each of those must end with the one invariant its cfg names
# violated. A config named *Reach-* names a state the design must be able to reach, as an invariant that says
# it never does, and must end with that invariant violated. Prints one verdict line per run with the states,
# depth and time TLC reported and the most its state directory held, sampled every 5 s, which section 15.3
# records.
#
#   run-indexerase.sh <track> [all | design | landed | twins | reach | <Config>]...
#
# Disk: the disk is shared with the build lanes, so every run is bounded on disk as well as in states. Every
# config runs breadth-first at bounds whose complete graph finishes. A run whose state directory passes
# TLC_DISK_CAP_MB (8,192 MB) is stopped and reported as FAIL (bounded), and every run's state directory is
# deleted when it ends. Each invocation names its own state directories, so two may run at once. TLC_FLAGS adds
# flags to any run, TLC_WORKERS sets its workers (4 unless set, since the host is shared) and TLC_HEAP its heap.
#
# exit: 0 every run did what it must; 1 one did not; 64 usage
set -uo pipefail
# The whole body is parsed before it runs, so editing this file never reaches a run in progress.
main() {
  here=$(cd "$(dirname "$0")" && pwd)
  ROOT=/Users/builder/urnetwork-sidecar
  [ $# -ge 1 ] || { echo "usage: run-indexerase.sh <track> [all | design | landed | twins | reach | <Config>]..." >&2; exit 64; }
  track=$1
  shift
  cap=${TLC_DISK_CAP_MB:-8192}
  designs="IndexErase IndexErase-Long IndexErase-Card IndexErase-CardLong"
  landed="IndexEraseLanded-ErasedBase"
  twins="IndexEraseTwin-NoReentry IndexEraseTwin-ClosureFirst IndexEraseTwin-KeepResting IndexEraseTwin-MergeDropsResting IndexEraseTwin-CutFirst IndexEraseTwin-NoSync IndexEraseTwin-NoBlock IndexEraseTwin-SeqVersion IndexEraseTwin-SeqVersion-Late"
  reach="IndexEraseReach-Owed IndexEraseReach-Reentered IndexEraseReach-Excused IndexEraseReach-ComposedThrough IndexEraseReach-Raced IndexEraseReach-Blocked IndexEraseReach-Returns IndexEraseReach-Twice"
  [ $# -ge 1 ] || set -- all
  configs=
  for name in "$@"; do
    case $name in
      all) configs="$configs $designs $landed $twins $reach" ;;
      design) configs="$configs $designs" ;;
      landed) configs="$configs $landed" ;;
      twins) configs="$configs $twins" ;;
      reach) configs="$configs $reach" ;;
      *) configs="$configs $name" ;;
    esac
  done
  set -- $configs
  # each invocation names its own state directories, so two at once never take each other's
  run=$track.$$
  metadirs() { ls -d "$ROOT/.stack/scratch/$run.tlc."* 2>/dev/null; }
  runner=
  before=
  # a stopped script stops its TLC and deletes the run's state directory, so a timeout never leaves a run going
  stop() {
    if [ -n "$runner" ]; then
      for pid in $(pgrep -P "$runner"); do kill -TERM "$pid" 2>/dev/null; done
      kill -TERM "$runner" 2>/dev/null
      sleep 2
      for pid in $(pgrep -P "$runner"); do kill -KILL "$pid" 2>/dev/null; done
    fi
    for dir in $(metadirs); do
      case " $before " in *" $dir "*) continue ;; esac
      rm -rf "$dir"
    done
  }
  trap 'stop; exit 1' TERM INT
  failed=0
  for config in "$@"; do
    case $config in
      IndexErase*) spec=IndexErase ;;
      *) echo "run-indexerase.sh: no spec for config $config" >&2; exit 64 ;;
    esac
    [ -f "$here/$config.cfg" ] || { echo "run-indexerase.sh: no config $config" >&2; exit 64; }
    mkdir -p "$ROOT/.stack/scratch/$track"
    out=$(mktemp "$ROOT/.stack/scratch/$track/indexerase.XXXXXX")
    flags=${TLC_FLAGS:-}
    before=$(metadirs)
    (cd "$here" && exec "$ROOT/.stack/tools/tlc" "$run" -config "$config.cfg" -workers "${TLC_WORKERS:-4}" $flags "$spec.tla") > "$out" 2>&1 &
    runner=$!
    bounded=0
    peak=0
    while kill -0 "$runner" 2>/dev/null; do
      sleep 5
      for dir in $(metadirs); do
        case " $before " in *" $dir "*) continue ;; esac
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
    for dir in $(metadirs); do
      case " $before " in *" $dir "*) continue ;; esac
      rm -rf "$dir"
    done
    rev=$(sed -n 's/.*(rev: \([0-9a-f]*\)).*/\1/p' "$out" | head -1)
    violated=$(sed -n 's/^Error: Invariant \(.*\) is violated.*/\1/p' "$out" | head -1)
    if [ -z "$violated" ]; then
      violated=$(sed -n 's/^Error: Temporal property \(.*\) was violated.*/\1/p' "$out" | head -1)
    fi
    distinct=$(sed -n 's/.* \([0-9,]*\) distinct states found.*/\1/p' "$out" | tail -1)
    depth=$(sed -n 's/^The depth of the complete state graph search is \([0-9]*\).*/\1/p' "$out" | tail -1)
    took=$(sed -n 's/^Finished in \(.*\) at .*/\1/p' "$out" | tail -1)
    trace=$(grep -c '^State [0-9]*:' "$out")
    # the last indented name of the cfg: the one invariant or property a twin must break
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
        *Landed-*|*Open-*|*Twin-*|*Reach-*)
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
