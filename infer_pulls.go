//go:build !ios_extension && !sidecar_http

// The pulls a device's surfaces share (DESIGN-COMPUTE §15.3, §15.4; INFER-M11-08, INFER-M11-09): one pull a model,
// running in its owner's context until it ends, whoever asked for it and whoever stopped listening; its status the same
// JSON on every surface, ur daemon's models.pull reply and notifications and an app's SidecarModelsPullListener, read
// now or followed to the end. ur daemon keeps one over the instance's InferPull, an app's Models() one over its core's,
// so two screens, or ur models pull and an app, asking for one model share its pull. A pull that ended is answered once:
// a status read after that starts it again, which for a whole file ends at once. Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"sync"
)

// A pull's states.
const (
	InferPullRunning = "running"
	InferPullDone    = "done"
	InferPullFailed  = "failed"
)

// A pull's status, as every surface shows it: running, done or failed, how far it is, and why it failed.
type InferPullStatus struct {
	// The name the pull was asked for.
	Name string `json:"name"`
	// running, done or failed.
	State    string             `json:"state"`
	Progress *InferPullProgress `json:"progress,omitempty"`
	Error    *InferPullError    `json:"error,omitempty"`
}

// Whether the status is a pull's end.
func (self *InferPullStatus) Ended() bool {
	return self.State != InferPullRunning
}

// What runs a pull: an InferPull's Pull, or a test's in its place.
type InferPullFunc func(ctx context.Context, name string, listener func(*InferPullProgress)) error

// A follower left before the pull ended: the pull goes on.
var ErrInferPullLeft = errors.New("the follower left; the pull goes on")

// One pull a model (see the file comment).
type InferPulls struct {
	ctx      context.Context
	pull     InferPullFunc
	settings *InferSettings

	stateLock  sync.Mutex
	nameStates map[string]*inferPullsState
}

// One pull's state: its newest status, and a channel closed and replaced at each change.
type inferPullsState struct {
	status  *InferPullStatus
	ended   bool
	changed chan struct{}
}

// Pulls run by pull in ctx, which ends them; settings nil for the defaults: how often a follower hears of an engine
// file's bytes, by ModelChunkByteCount.
func NewInferPulls(ctx context.Context, pull InferPullFunc, settings *InferSettings) *InferPulls {
	if settings == nil {
		settings = DefaultInferSettings()
	}
	return &InferPulls{ctx: ctx, pull: pull, settings: settings, nameStates: map[string]*inferPullsState{}}
}

// name's pull: the one running, or ended and not yet answered, else a new one started. A state taken after it ended
// is forgotten, so it is answered once.
func (self *InferPulls) join(name string) (*inferPullsState, *InferPullStatus, chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state, ok := self.nameStates[name]
	if !ok {
		state = &inferPullsState{
			status:  &InferPullStatus{Name: name, State: InferPullRunning},
			changed: make(chan struct{}),
		}
		self.nameStates[name] = state
		go self.run(name, state)
	}
	return state, self.takeWithLock(name, state), state.changed
}

// The state's status now, forgetting the state where it ended. Called with stateLock held.
func (self *InferPulls) takeWithLock(name string, state *inferPullsState) *InferPullStatus {
	status := *state.status
	if state.ended && self.nameStates[name] == state {
		delete(self.nameStates, name)
	}
	return &status
}

// The state's status now and the channel its next change closes, forgetting it where it ended.
func (self *InferPulls) read(name string, state *inferPullsState) (*InferPullStatus, chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.takeWithLock(name, state), state.changed
}

// Sets the state's status by change, and wakes its followers.
func (self *InferPulls) update(state *inferPullsState, change func(status *InferPullStatus)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	status := *state.status
	change(&status)
	state.status = &status
	close(state.changed)
	state.changed = make(chan struct{})
}

// Runs name's pull to its end in the pulls' context.
func (self *InferPulls) run(name string, state *inferPullsState) {
	err := self.pull(self.ctx, name, func(progress *InferPullProgress) {
		copied := *progress
		self.update(state, func(status *InferPullStatus) {
			status.Progress = &copied
		})
	})
	self.update(state, func(status *InferPullStatus) {
		if err != nil {
			status.State = InferPullFailed
			status.Error = InferPullErrorOf(err)
		} else {
			status.State = InferPullDone
		}
	})
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state.ended = true
	}()
	// a follower waiting now reads the end
	self.update(state, func(status *InferPullStatus) {})
}

// Whether next is news to a follower that last heard last: another state, phase, file or chunk, or an engine file's
// bytes past another ModelChunkByteCount.
func (self *InferPulls) news(last *InferPullStatus, next *InferPullStatus) bool {
	if last == nil || last.State != next.State || (last.Progress == nil) != (next.Progress == nil) {
		return true
	}
	if next.Progress == nil {
		return false
	}
	a, b := last.Progress, next.Progress
	return a.Phase != b.Phase || a.FileIndex != b.FileIndex || a.DoneChunkCount != b.DoneChunkCount ||
		self.settings.ModelChunkByteCount <= b.DoneByteCount-a.DoneByteCount
}

// name's pull's status now, the pull joined or started: models.pull without follow, which an app polls.
func (self *InferPulls) Status(name string) *InferPullStatus {
	_, status, _ := self.join(name)
	return status
}

// Follows name's pull, joined or started, telling tell each running status that is news to it until the pull ends,
// and answers the end: or ctx's error, or ErrInferPullLeft once left closes (nil never closes), the pull going on
// either way. A status tell refuses is told again with the next news.
func (self *InferPulls) Follow(ctx context.Context, name string, left <-chan struct{}, tell func(*InferPullStatus) error) (*InferPullStatus, error) {
	state, status, changed := self.join(name)
	var heard *InferPullStatus
	for !status.Ended() {
		if self.news(heard, status) {
			if err := tell(status); err == nil {
				heard = status
			}
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-left:
			return nil, ErrInferPullLeft
		}
		status, changed = self.read(name, state)
	}
	return status, nil
}
