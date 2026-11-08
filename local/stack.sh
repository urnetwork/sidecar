#!/usr/bin/env bash
# The local stack of §22.4, shared by every track on this machine.
#
# usage: local/stack.sh up       starts the stores and forms the cluster, returning once both answer
#        local/stack.sh down     stops them and drops what they held, refused while a test holds them
#        local/stack.sh status   says what is up
#        local/stack.sh test     runs the store suites on them, starting the stack if it is down, and
#                                stopping a stack a test started once no other run still holds it
#
# GO names the go to test with, as make check's does. A run of test holds the stack by keeping a process
# of a known name alive, so one track's run never stops the stack under another's, and a run that dies
# leaves nothing to clean up: its hold ends when that process does. A stack a test started says so in a
# file inside a node, which goes with the node, so the last run out stops it whoever started it, and a
# stack started by hand stays up.
#
# Two starts at once need no lock. Compose brings up what is missing, and of two cluster creates the
# second finds its slots taken and fails, which is why a failed create is not the end: what counts is
# whether the cluster is formed afterwards.
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(dirname "$here")
GO=${GO:-go}
compose=(docker compose -f "$here/docker-compose.yml")
masters=(sidecar-test-redis-cluster-0:56401 sidecar-test-redis-cluster-1:56402 sidecar-test-redis-cluster-2:56403)
minio_health=http://127.0.0.1:59000/minio/health/cluster
started_mark=/tmp/started-by-test
holder_name=sidecar-test-stack-holder
# past any run's own timeouts, so a run that dies stops holding soon after
holder_seconds=900
# how long, in tenths of a second, a store may take to answer: 60 s
wait_tenths=600
holder=""

cluster_formed() {
  local node info
  for node in "${masters[@]}"; do
    info=$(docker exec "${node%:*}" redis-cli -p "${node#*:}" cluster info 2>/dev/null) || return 1
    grep -q '^cluster_state:ok' <<<"$info" || return 1
    grep -q '^cluster_known_nodes:3' <<<"$info" || return 1
  done
}

minio_answers() {
  curl -sf -o /dev/null "$minio_health"
}

stack_up() {
  cluster_formed && minio_answers
}

# CLUSTER MEET takes ips, and only the stack's network can name them.
form_cluster() {
  docker exec sidecar-test-redis-cluster-0 sh -c '
    set -e
    for name in redis-0:56401:56411 redis-1:56402:56412 redis-2:56403:56413; do
      host=${name%%:*}; ports=${name#*:}
      ip=$(getent hosts "$host" | cut -d" " -f1)
      nodes="$nodes $ip:${ports%:*}@${ports#*:}"
    done
    redis-cli --cluster create $nodes --cluster-replicas 0 --cluster-yes
  ' >/dev/null 2>&1
}

wait_for() {
  local what=$1 waited=0
  shift
  until "$@"; do
    waited=$((waited + 1))
    [ $waited -lt $wait_tenths ] || { echo "$what did not come up" >&2; return 1; }
    sleep 0.1
  done
}

up() {
  stack_up && return 0
  "${compose[@]}" up -d --wait --quiet-pull || return 1
  cluster_formed || form_cluster
  wait_for "the Redis Cluster" cluster_formed || return 1
  wait_for "MinIO" minio_answers
}

hold() {
  (exec -a "$holder_name" sleep "$holder_seconds") &
  holder=$!
}

release() {
  if [ -n "$holder" ]; then
    kill "$holder" 2>/dev/null
    wait "$holder" 2>/dev/null
    holder=""
  fi
}

# The holds other than this run's.
other_holders() {
  local pid
  for pid in $(pgrep -f "$holder_name"); do
    [ "$pid" = "$holder" ] || echo "$pid"
  done
}

down() {
  local others
  others=$(other_holders)
  if [ -n "$others" ]; then
    echo "held by pid $others, so left up" >&2
    return 3
  fi
  "${compose[@]}" down -v --remove-orphans
}

status() {
  "${compose[@]}" ps
  if stack_up; then echo "up"; else echo "not up"; fi
}

run_suites() {
  (cd "$root" && "$GO" test -count=1 -timeout 280s -tags sidecar_localstack ./sidecartest/localstack) &&
    (cd "$root" && "$GO" test -count=1 -timeout 280s -tags sidecar_localstack,sidecar_testhooks ./sidecartest/localstack)
}

test_stack() {
  local result=1 others
  hold
  trap release EXIT
  if stack_up; then
    run_suites
    result=$?
  elif up; then
    docker exec sidecar-test-redis-cluster-0 touch "$started_mark"
    run_suites
    result=$?
  else
    down
    return 1
  fi
  release
  others=$(other_holders)
  if [ -z "$others" ] && docker exec sidecar-test-redis-cluster-0 test -e "$started_mark" 2>/dev/null; then
    down
  fi
  return $result
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  test) test_stack ;;
  *) echo "usage: local/stack.sh up|down|status|test" >&2; exit 64 ;;
esac
