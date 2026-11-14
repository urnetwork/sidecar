#!/bin/sh
# §22.8's twenty-agent test at its published length (EVS1-M2-43; R-TEST-7; DESIGN-DETAILS 8.6): twenty agents, each
# a device of its own on T2's in-process evs, push their owned refs and merge into main every 60 s for an hour, then
# the run checks that no acknowledged commit was lost, that no device made a conflict branch, that git fsck --strict
# passes on a device that pushed nothing, and that export's main equals its replay. It writes load's report to the
# file it is given (default twenty-agents-report.json in the current directory).
#
# Run it on a host whose CPU no test campaign shares: it is never part of go test's default run, which takes the
# smoke form, and it never takes tests/network-intensive-suite-lock.sh. SIDECAR_EVS_AGENTS=ci instead of hour runs
# §22.8's five-minute CI form.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
report=${1:-$(pwd)/twenty-agents-report.json}
form=${SIDECAR_EVS_AGENTS:-hour}
cd "$here/.."
SIDECAR_EVS_AGENTS="$form" SIDECAR_EVS_AGENTS_REPORT="$report" \
	go test -count=1 -timeout 3h -run '^TestEvsTwentyAgents$' ./sidecartest
echo "twenty agents ($form): report at $report"
