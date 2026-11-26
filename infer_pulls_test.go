//go:build !ios_extension && !sidecar_http && !js

package sidecar

// The pulls a device's surfaces share (infer_pulls.go): one pull a model however many follow it, a follower that leaves
// leaving it running, and its end answered to each follower and then once more, after which a read starts it again.

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// A pull held at a gate: it reports one chunk, waits for release, then ends with end.
type testInferPullsGate struct {
	stateLock sync.Mutex
	started   int
	release   chan struct{}
	end       error
}

func (self *testInferPullsGate) pull(ctx context.Context, name string, listener func(*InferPullProgress)) error {
	self.stateLock.Lock()
	self.started += 1
	self.stateLock.Unlock()
	listener(&InferPullProgress{Name: name, Phase: InferPullPhaseModel, ChunkCount: 2, DoneChunkCount: 1})
	select {
	case <-self.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	listener(&InferPullProgress{Name: name, Phase: InferPullPhaseModel, ChunkCount: 2, DoneChunkCount: 2})
	return self.end
}

func (self *testInferPullsGate) startedCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.started
}

// Two followers share one pull; one that leaves leaves it running; both hear the end, which is answered once.
func TestPullsShareOnePullAndOutliveAFollower(t *testing.T) {
	gate := &testInferPullsGate{release: make(chan struct{})}
	pulls := NewInferPulls(context.Background(), gate.pull, nil)
	heardChunk := make(chan struct{}, 4)
	tell := func(status *InferPullStatus) error {
		if status.Progress != nil && status.Progress.DoneChunkCount == 1 {
			heardChunk <- struct{}{}
		}
		return nil
	}
	ends := make(chan *InferPullStatus, 2)
	for range 2 {
		go func() {
			end, err := pulls.Follow(context.Background(), "local-test-model-off", nil, tell)
			if err != nil {
				t.Error(err)
			}
			ends <- end
		}()
	}
	// a third follower leaves once it has heard the first chunk
	left := make(chan struct{})
	leave := sync.OnceFunc(func() { close(left) })
	leftEnd := make(chan error, 1)
	go func() {
		_, err := pulls.Follow(context.Background(), "local-test-model-off", left, func(status *InferPullStatus) error {
			if status.Progress != nil {
				leave()
			}
			return nil
		})
		leftEnd <- err
	}()
	if err := <-leftEnd; !errors.Is(err, ErrInferPullLeft) {
		t.Fatalf("the follower that left answered %v", err)
	}
	<-heardChunk
	<-heardChunk
	close(gate.release)
	for range 2 {
		if end := <-ends; end.State != InferPullDone || end.Progress == nil || end.Progress.DoneChunkCount != 2 {
			t.Errorf("a follower's end %+v", end)
		}
	}
	if gate.startedCount() != 1 {
		t.Errorf("%d pulls ran for one model", gate.startedCount())
	}
	// the end was taken by the followers: a read now starts the pull again
	gate.end = errors.New("the disk is gone")
	gate.release = make(chan struct{})
	close(gate.release)
	status := pulls.Status("local-test-model-off")
	if status.Ended() {
		t.Errorf("a read after the end answered %+v", status)
	}
	end, err := pulls.Follow(context.Background(), "local-test-model-off", nil, func(*InferPullStatus) error { return nil })
	if err != nil || end.State != InferPullFailed || end.Error == nil || end.Error.Code != "pull_failed" {
		t.Errorf("the second pull ended %+v, %v", end, err)
	}
	if gate.startedCount() != 2 {
		t.Errorf("%d pulls ran", gate.startedCount())
	}
}
