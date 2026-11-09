// A fake of §7.10's group view (sidecar.SidecarStaleGroupView), which KEYS-M4-01's gkm client provides for real: each
// page Worker's leaf in each group the admitting device is a leaf of, as a test sets it, and every stale Remove the
// device commits. FS-97's schedule (TEAM-M4-01) runs CORE-M4-02's act on it until the real view lands.
//
// Safe for concurrent use.

package sidecartest

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// The fake. Construct with NewFakeStaleGroupView.
type FakeStaleGroupView struct {
	stateLock sync.Mutex
	leaves    map[sidecar.Id][]*sidecar.SidecarStaleLeaf
	commits   []FakeStaleRemove
	// answered by every call while set
	err error
	// run before each StaleLeaves answer, outside the lock: a schedule's step between a decision and its re-check
	beforeAnswer func()
}

// One stale Remove the device committed.
type FakeStaleRemove struct {
	GroupId  sidecar.Id
	WorkerId sidecar.Id
}

var _ sidecar.SidecarStaleGroupView = (*FakeStaleGroupView)(nil)

// A view of no group.
func NewFakeStaleGroupView() *FakeStaleGroupView {
	return &FakeStaleGroupView{leaves: map[sidecar.Id][]*sidecar.SidecarStaleLeaf{}}
}

// Sets workerId's leaf in groupId at epoch, replacing any before: removed, due or live, the device a writer leaf there
// or not, with its leaf's last change.
func (self *FakeStaleGroupView) SetLeaf(groupId sidecar.Id, workerId sidecar.Id, epoch uint64, state sidecar.SidecarStaleLeafState,
	writer bool, lastChange time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	leaves := slices.DeleteFunc(self.leaves[workerId], func(leaf *sidecar.SidecarStaleLeaf) bool { return leaf.GroupId == groupId })
	self.leaves[workerId] = append(leaves, &sidecar.SidecarStaleLeaf{
		GroupId:    groupId,
		WorkerId:   workerId,
		Epoch:      epoch,
		State:      state,
		Writer:     writer,
		LastChange: lastChange,
	})
}

// Takes workerId's leaf in groupId away: no group of the device seated it there.
func (self *FakeStaleGroupView) ClearLeaf(groupId sidecar.Id, workerId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.leaves[workerId] = slices.DeleteFunc(self.leaves[workerId], func(leaf *sidecar.SidecarStaleLeaf) bool { return leaf.GroupId == groupId })
}

// Makes every call answer err; nil restores.
func (self *FakeStaleGroupView) SetErr(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.err = err
}

// Runs step before each StaleLeaves answer; nil removes it.
func (self *FakeStaleGroupView) SetBeforeAnswer(step func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.beforeAnswer = step
}

// The stale Removes committed so far, in order.
func (self *FakeStaleGroupView) Commits() []FakeStaleRemove {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.commits)
}

// Each asked Worker's leaves as set, copies, after the step SetBeforeAnswer gave.
func (self *FakeStaleGroupView) StaleLeaves(ctx context.Context, workerIds []sidecar.Id) ([]*sidecar.SidecarStaleLeaf, error) {
	self.stateLock.Lock()
	beforeAnswer := self.beforeAnswer
	self.stateLock.Unlock()
	if beforeAnswer != nil {
		beforeAnswer()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.err != nil {
		return nil, self.err
	}
	answer := []*sidecar.SidecarStaleLeaf{}
	for _, workerId := range workerIds {
		for _, leaf := range self.leaves[workerId] {
			copied := *leaf
			answer = append(answer, &copied)
		}
	}
	return answer, nil
}

// Commits a due Remove: the leaf reads removed from here on. Refuses a leaf that is not due, as a member would.
func (self *FakeStaleGroupView) CommitStaleRemove(ctx context.Context, groupId sidecar.Id, workerId sidecar.Id) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.err != nil {
		return self.err
	}
	for _, leaf := range self.leaves[workerId] {
		if leaf.GroupId != groupId {
			continue
		}
		if leaf.State != sidecar.SidecarStaleLeafDue || !leaf.Writer {
			return errors.New("fake stale group view: no due Remove of that leaf for this device")
		}
		leaf.State = sidecar.SidecarStaleLeafRemoved
		leaf.Epoch += 1
		self.commits = append(self.commits, FakeStaleRemove{GroupId: groupId, WorkerId: workerId})
		return nil
	}
	return errors.New("fake stale group view: no such leaf")
}
