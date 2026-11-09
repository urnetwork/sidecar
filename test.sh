#!/usr/bin/env bash
# §22.4's T1 and T2 entry point, which tests/run-all.sh calls after connect (D-TEST-1; TEST-M0-04).
#
#   test.sh [--cadence merge|nightly|gate] [--gate Mn] [--legs] [--dry-run]
#
# Each cadence is a list of phases, run in order, each printing its success footer when it passes:
#
#   merge, the default, on each merge (QD-374: T1, T2 and T3's store suites gate merges):
#     race <module>       go test -race -count=1 ./... in each module of the Makefile's list
#     testhooks <module>  the same under sidecar_testhooks, which runs fuzz seeds as ordinary tests (owner
#                         decision 101), T2's FS rows and their 10 explorer seeds (§22.8)
#     leak                §22.7's self-test under sidecar_leaktest, with -race (make check runs it without)
#     check               make check: every module's tests again without -race, then check/'s rules
#     t3-suites           ../server/sidecar-t3.sh suites: T3's store suites on real stores, when that
#                         sibling exists, since sidecar never requires server
#   nightly, the merge phases and then:
#     legs                the every-leg runner (sidecartest/legs, TEST-M1-07)
#     stack               make stack-test: the store suites on §22.4's local stack, which needs Docker
#     t3                  ../server/sidecar-t3.sh nightly: T3's FS rows and their 100 explorer seeds
#   gate, the nightly phases and then, for --gate Mn:
#     model               the TLC runs of sidecartest/model in gate mode (TEST-M2-08), with TLC naming
#                         the command that runs tlc2.TLC; with no TLC the gate fails, naming the tool
#     gate-report         ../server/local/sidecar-gate Mn, OPS-M1-07's report of the gate's rows
#
# --legs runs the legs phase alone. --dry-run prints each phase's commands and runs none.
#
# tests/RUN-ALL.md's clean full-run criteria hold here: the exit status is the verdict; a phase that
# fails ends the run at once and prints no footer for itself; nothing is retried, so a failed attempt
# fails the run whatever a second one would do (R-TEST-9, tests/RUN-ALL.md:986), and every go test runs
# with -count=1, since go test's cache would hide a new failure; GOMAXPROCS is inherited unchanged;
# WARP_TEST_ENV_FAIL_FAST=1, so server's test env does not rerun a failed attempt either; and a phase
# runs in its own process group, which an interrupt takes down whole, so no process is left behind.
# A phase that cannot run here prints "not run" and its reason, which is never a pass: merge and
# nightly go on without it, and gate, whose report must be whole, fails.
#
# This script takes no suite lock: tests/run-all.sh holds the network-intensive lock around it, and
# nothing here may take that lock itself.
#
# GO names the go command (as in GO=lowgo), MAKE the make command, TEST_TIMEOUT go test's -timeout.
#
# exit: 0 every phase that ran passed; the failing phase's status otherwise; 64 usage; 130 or 143 on
# an interrupt.

set -u

here=$(cd "$(dirname "$0")" && pwd)
GO=${GO:-go}
MAKE=${MAKE:-make}
TEST_TIMEOUT=${TEST_TIMEOUT:-30m}
export WARP_TEST_ENV_FAIL_FAST=1

usage() {
  sed -n '4p' "$0" | sed 's/^# *//' >&2
  exit 64
}

cadence=merge
gate=""
legs_only=0
dry_run=0
while [ $# -gt 0 ]; do
  case $1 in
    --cadence)
      [ $# -ge 2 ] || usage
      cadence=$2
      shift 2
      ;;
    --cadence=*)
      cadence=${1#--cadence=}
      shift
      ;;
    --gate)
      [ $# -ge 2 ] || usage
      gate=$2
      shift 2
      ;;
    --gate=*)
      gate=${1#--gate=}
      shift
      ;;
    --legs)
      legs_only=1
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    *)
      echo "test.sh: unknown argument $1" >&2
      usage
      ;;
  esac
done
case $cadence in
  merge|nightly) ;;
  gate)
    case $gate in
      M[0-9]|M10) ;;
      *)
        echo "test.sh: --cadence gate needs --gate M0 to M10, not \"$gate\"" >&2
        exit 64
        ;;
    esac
    ;;
  *)
    echo "test.sh: unknown cadence \"$cadence\": merge, nightly or gate" >&2
    exit 64
    ;;
esac
if [ -n "$gate" ] && [ "$cadence" != gate ]; then
  echo "test.sh: --gate goes with --cadence gate" >&2
  exit 64
fi

say() {
  printf '[sidecar test.sh] %s\n' "$*"
}

# The Makefile's module list, as make itself evaluates it, so a release tree's list is read too.
modules=$(cd "$here" && printf 'test-sh-modules:\n\t@echo $(modules)\n' |
  "$MAKE" --no-print-directory -s -f Makefile -f - test-sh-modules) || {
  echo "test.sh: cannot read the Makefile's module list" >&2
  exit 1
}
[ -n "$modules" ] || {
  echo "test.sh: the Makefile lists no module" >&2
  exit 1
}

# An interrupt takes down every phase's process group, the one starting included, and waits for it.
on_signal() {
  local signal=$1 status=$2 job
  for job in $(jobs -p); do
    kill -TERM -- "-$job" 2>/dev/null
  done
  wait 2>/dev/null
  say "interrupted by $signal: the run is not a pass"
  exit "$status"
}
trap 'on_signal INT 130' INT
trap 'on_signal TERM 143' TERM
# each phase in a process group of its own, so the handler can take it down whole
set -m

not_run=""
ran=0

# Runs one phase: its name, the directory it runs in, then its command. A failure ends the run.
phase() {
  local name=$1 directory=$2 started status
  shift 2
  say "phase $name: $*"
  if [ "$dry_run" = 1 ]; then
    return 0
  fi
  started=$(date +%s)
  (cd "$directory" && exec "$@") &
  wait "$!"
  status=$?
  if [ "$status" -ne 0 ]; then
    say "phase $name failed with status $status; nothing is retried, so the run fails"
    exit "$status"
  fi
  ran=$((ran + 1))
  say "phase $name ok in $(($(date +%s) - started))s"
}

# A phase that cannot run here: never a pass.
skip() {
  local name=$1 reason=$2
  say "phase $name: not run ($reason)"
  not_run="${not_run:+$not_run, }$name"
}

legs_phase() {
  phase legs "$here" "$GO" test -count=1 -timeout 0 -tags sidecar_legs -run '^TestEveryLegRuns$' ./sidecartest/legs
}

if [ "$legs_only" = 1 ]; then
  legs_phase
  say "--legs: every phase ok"
  exit 0
fi

for module in $modules; do
  phase "race $module" "$here/$module" "$GO" test -race -count=1 -timeout "$TEST_TIMEOUT" ./...
  phase "testhooks $module" "$here/$module" "$GO" test -race -count=1 -timeout "$TEST_TIMEOUT" -tags sidecar_testhooks ./...
done
phase leak "$here" "$GO" test -race -count=1 -timeout "$TEST_TIMEOUT" -tags sidecar_leaktest ./sidecartest/...
phase check "$here" "$MAKE" check GO="$GO" TEST_TIMEOUT="$TEST_TIMEOUT"

server=$here/../server
if [ -x "$server/sidecar-t3.sh" ]; then
  phase t3-suites "$server" ./sidecar-t3.sh suites
else
  skip t3-suites "../server/sidecar-t3.sh is not there; TEST-M1-08 adds it"
fi

if [ "$cadence" = nightly ] || [ "$cadence" = gate ]; then
  legs_phase
  phase stack "$here" "$MAKE" stack-test GO="$GO"
  if [ -x "$server/sidecar-t3.sh" ]; then
    phase t3 "$server" ./sidecar-t3.sh nightly
  else
    skip t3 "../server/sidecar-t3.sh is not there; TEST-M1-08 adds it"
  fi
fi

if [ "$cadence" = gate ]; then
  phase model "$here" env SIDECAR_TLC_MODE=gate "$GO" test -count=1 -timeout 0 -tags sidecar_tlc ./sidecartest/model
  if [ -d "$server/local/sidecar-gate" ]; then
    phase gate-report "$server" "$GO" run ./local/sidecar-gate "$gate"
  else
    skip gate-report "../server/local/sidecar-gate is not there; OPS-M1-07 adds it"
  fi
fi

if [ "$dry_run" = 1 ]; then
  say "cadence $cadence: dry run, nothing ran"
  exit 0
fi
if [ -n "$not_run" ]; then
  if [ "$cadence" = gate ]; then
    say "cadence gate $gate: not run: $not_run; a gate's report must be whole, so the run fails"
    exit 1
  fi
  say "cadence $cadence: $ran phases ok; not run, which is no pass: $not_run"
  exit 0
fi
say "cadence $cadence${gate:+ $gate}: every phase ok ($ran phases)"
exit 0
