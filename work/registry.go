// taskworker's work (owner decision 594; CSRV-M12-05): sidecar's jobs that server's taskworker runs, each a name and
// one run over its args, which reads the process's global Env (operator.GlobalEnv) and passes it to sidecar/model and
// sidecar/controller, so no job names a server type. Each area registers its jobs from an init in its own
// sidecar/work/<area>_*.go file through RegisterJob, as mcp/'s tools register, and taskworker binds each registered
// name in its sidecar task registry and schedules it by its design (registry_compute.go's for compute's), so no area
// edits taskworker to add one.
//
// A job's name is its key in every request for it and never changes: a removed job's name is kept from reuse, as
// server/task keeps a removed target's.
//
// The registry is written at init and read by taskworker once it starts; its lock makes a late registration safe.

package work

import (
	"context"
	"fmt"
	"slices"
	"sync"
)

// One of sidecar's taskworker jobs.
type Job struct {
	// The job's name, which every request for it names.
	Name string
	// One run over args: idempotent and resuming from durable state, since it may run again after a crash or an
	// error. It answers the args of the run that continues it where it stopped partway with more to do, nil where it
	// finished, or failed with nothing to resume from; a run that answers an error and no args is run again on
	// server/task's backoff.
	Run func(ctx context.Context, args []byte) ([]byte, error)
}

var (
	jobsStateLock sync.Mutex
	nameJobs      = map[string]*Job{}
)

// Registers job from an init in its own file. A nil job, one with no name or run, or a second job of one name is a
// build error, which panics.
func RegisterJob(job *Job) {
	if job == nil || job.Name == "" || job.Run == nil {
		panic("work: a job needs a name and a run")
	}
	jobsStateLock.Lock()
	defer jobsStateLock.Unlock()
	if _, registered := nameJobs[job.Name]; registered {
		panic(fmt.Sprintf("work: %s registered twice", job.Name))
	}
	nameJobs[job.Name] = job
}

// The job registered under name, nil for none.
func RegisteredJob(name string) *Job {
	jobsStateLock.Lock()
	defer jobsStateLock.Unlock()
	return nameJobs[name]
}

// Every registered job's name, sorted.
func RegisteredJobNames() []string {
	jobsStateLock.Lock()
	defer jobsStateLock.Unlock()
	names := make([]string, 0, len(nameJobs))
	for name := range nameJobs {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
