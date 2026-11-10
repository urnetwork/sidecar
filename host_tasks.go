//go:build !sidecar_http && !ios_extension

// ServiceHost.Tasks: taskworker's jobs (§19.4), by name, since an engine cannot name server's generic
// task functions. Evacuation, GC, packing, shreds, gkm's reconciler, drop jobs and certs run here.
// The loops §19.4 calls continuous, the push sender and the write budget's, are not jobs: taskworker
// runs them on their own goroutines.

package sidecar

import (
	"context"
	"time"
)

// One run of a job. It may run again after a crash or an error, so it is idempotent, and it resumes
// from durable state rather than from args alone (connect/CODESTYLE.md:135). ctx ends at the job's
// MaxTime and at shutdown. A non-nil error reruns it after the host's backoff.
type TaskFunction func(ctx context.Context, args []byte) error

// One request to run a job.
type TaskRequest struct {
	// The registered job.
	Name string
	// Requests with one key coalesce while pending, so asking twice runs once: the once-keyed
	// jobs of §4.5. A request during a run owns one successor after that run ends, with the running
	// args left alone. Required, and an opaque id, never content (I-13).
	OnceKey string
	// Opaque to the host. Stored until the run, so ids and positions only, never a secret or content.
	Args []byte
	// Not before this. Zero: at once. A job that repeats, such as the hourly evacuation, schedules
	// its next run under its own key before it returns.
	RunAt time.Time
	// How long one run may take. Zero: the host's default.
	MaxTime time.Duration
}

// taskworker's queue, by job name. Safe for concurrent use.
type Tasks interface {
	// Binds a job to its name, in the process that runs it, before that process claims work. A second
	// function for one name is the caller's bug, and the host panics.
	Register(name string, function TaskFunction)
	// Queues a run durably: a nil return means it will run. From any process, whether or not it
	// registered the job.
	Schedule(ctx context.Context, request *TaskRequest) error
}
