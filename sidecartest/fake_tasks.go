// ServiceHost.Tasks in memory (host_tasks.go): taskworker's once-keyed jobs on the injected clock.
// Nothing runs by itself. A test calls RunDue, which is what a claim loop would do, so a job runs at a
// point the test chose, and a run that crashes leaves its request where a restarted worker finds it.

package sidecartest

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

type FakeTasksSettings struct {
	// The host's backoff before a failed run reruns.
	RetryTimeout time.Duration
	// A run's MaxTime when its request gives none.
	DefaultMaxTime time.Duration
}

func DefaultFakeTasksSettings() *FakeTasksSettings {
	return &FakeTasksSettings{
		RetryTimeout:   1 * time.Minute,
		DefaultMaxTime: 1 * time.Hour,
	}
}

type fakeTask struct {
	request *sidecar.TaskRequest
	seq     uint64
	// a run of this key is in progress, and this request is its successor
	waitsForRun bool
}

type FakeTasks struct {
	clock    Clock
	faults   *FaultQueue
	settings *FakeTasksSettings

	stateLock sync.Mutex
	functions map[string]sidecar.TaskFunction
	seq       uint64
	pending   []*fakeTask
	running   map[string]*fakeTask
	runCounts map[string]int
}

func NewFakeTasks(clock Clock, faults *FaultQueue, settings *FakeTasksSettings) *FakeTasks {
	if settings == nil {
		settings = DefaultFakeTasksSettings()
	}
	return &FakeTasks{
		clock:     clock,
		faults:    faults,
		settings:  settings,
		functions: map[string]sidecar.TaskFunction{},
		running:   map[string]*fakeTask{},
		runCounts: map[string]int{},
	}
}

func (self *FakeTasks) Register(name string, function sidecar.TaskFunction) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, exists := self.functions[name]; exists {
		panic(fmt.Sprintf("a second function for job %q", name))
	}
	self.functions[name] = function
}

func (self *FakeTasks) pendingWithLock(onceKey string) *fakeTask {
	for _, task := range self.pending {
		if task.request.OnceKey == onceKey {
			return task
		}
	}
	return nil
}

func (self *FakeTasks) Schedule(ctx context.Context, request *sidecar.TaskRequest) error {
	if request.OnceKey == "" {
		return errors.New("a task request needs a OnceKey")
	}
	return hostCall(ctx, self.faults, "tasks.Schedule", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		requestCopy := *request
		requestCopy.Args = bytes.Clone(request.Args)
		if existing := self.pendingWithLock(request.OnceKey); existing != nil {
			// asking twice runs once, at the sooner time
			if requestCopy.RunAt.Before(existing.request.RunAt) {
				existing.request.RunAt = requestCopy.RunAt
			}
			return nil
		}
		self.seq += 1
		_, running := self.running[request.OnceKey]
		self.pending = append(self.pending, &fakeTask{request: &requestCopy, seq: self.seq, waitsForRun: running})
		return nil
	})
}

// Requests not yet run, oldest first, each a copy.
func (self *FakeTasks) Pending() []*sidecar.TaskRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	requests := make([]*sidecar.TaskRequest, 0, len(self.pending))
	for _, task := range self.pending {
		requestCopy := *task.request
		requests = append(requests, &requestCopy)
	}
	return requests
}

// Runs a job name has completed or failed, for a test's count.
func (self *FakeTasks) RunCount(name string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.runCounts[name]
}

// Takes the next request due, oldest first, skipping one whose key is running. nil: none is due.
func (self *FakeTasks) claimWithLock() *fakeTask {
	now := self.clock.Now()
	due := []*fakeTask{}
	for _, task := range self.pending {
		if !task.waitsForRun && !now.Before(task.request.RunAt) {
			due = append(due, task)
		}
	}
	if len(due) == 0 {
		return nil
	}
	claimed := slices.MinFunc(due, func(a *fakeTask, b *fakeTask) int { return cmp.Compare(a.seq, b.seq) })
	self.pending = slices.DeleteFunc(self.pending, func(task *fakeTask) bool { return task == claimed })
	self.running[claimed.request.OnceKey] = claimed
	return claimed
}

// A run's end: a successor waiting on it is free to run. A failed run goes back with its own args
// unless a successor already holds its key, which then carries on.
func (self *FakeTasks) finish(task *fakeTask, err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.runCounts[task.request.Name] += 1
	delete(self.running, task.request.OnceKey)
	successor := self.pendingWithLock(task.request.OnceKey)
	if successor != nil {
		successor.waitsForRun = false
		return
	}
	if err != nil {
		task.request.RunAt = self.clock.Now().Add(self.settings.RetryTimeout)
		self.pending = append(self.pending, task)
	}
}

// Runs every request due now, one at a time, on this goroutine, and returns how many ran. A request
// for a job nothing registered stays pending, and its name comes back as the error, since a process
// that claims work it has no function for is misconfigured. A run's own error is not returned: the
// host's backoff handles it, and RunCount and Pending show it.
func (self *FakeTasks) RunDue(ctx context.Context) (int, error) {
	ran := 0
	for {
		var task *fakeTask
		var function sidecar.TaskFunction
		unregistered := ""
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			task = self.claimWithLock()
			if task == nil {
				return
			}
			var ok bool
			function, ok = self.functions[task.request.Name]
			if !ok {
				unregistered = task.request.Name
				delete(self.running, task.request.OnceKey)
				self.pending = append(self.pending, task)
			}
		}()
		if unregistered != "" {
			return ran, fmt.Errorf("no function for job %q", unregistered)
		}
		if task == nil {
			return ran, nil
		}
		maxTime := task.request.MaxTime
		if maxTime == 0 {
			maxTime = self.settings.DefaultMaxTime
		}
		runCtx, cancel := context.WithCancel(ctx)
		stop := self.clock.AfterFunc(maxTime, cancel)
		err := function(runCtx, bytes.Clone(task.request.Args))
		stop()
		cancel()
		self.finish(task, err)
		ran += 1
	}
}

// A worker died mid-run: every run in progress goes back to pending, as a claim's lapse does.
func (self *FakeTasks) ReclaimRunning() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	reclaimed := 0
	for onceKey, task := range self.running {
		delete(self.running, onceKey)
		if successor := self.pendingWithLock(onceKey); successor != nil {
			successor.waitsForRun = false
		} else {
			self.pending = append(self.pending, task)
		}
		reclaimed += 1
	}
	return reclaimed
}
