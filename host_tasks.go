//go:build !sidecar_http && !ios_extension

// ServiceHost.Tasks: taskworker's jobs (§19.4), by name, since an engine cannot name server's generic
// task functions. Evacuation, GC, packing, shreds, gkm's reconciler, drop jobs and certs run here.
// The loops §19.4 calls continuous, the push sender and the write budget's, are not jobs: taskworker
// runs them on their own goroutines.
//
// The types are operator-core's (owner decision 251).

package sidecar

import (
	operator "github.com/urnetwork/operator-core"
)

// One run of a job: idempotent, resuming from durable state. A non-nil error reruns it after the host's
// backoff.
type TaskFunction = operator.TaskFunction

// One request to run a job.
type TaskRequest = operator.TaskRequest

// taskworker's queue, by job name.
type Tasks = operator.Tasks
