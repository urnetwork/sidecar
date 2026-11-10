package sidecartest

import (
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// The fake answers what a test set, commits only a due Remove its device may make, and reads removed after.
func TestFakeStaleGroupViewCommitsOnlyDueRemoves(t *testing.T) {
	view := NewFakeStaleGroupView()
	groupId := sidecar.NewId()
	due := sidecar.NewId()
	live := sidecar.NewId()
	lastChange := time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)
	view.SetLeaf(groupId, due, 4, sidecar.SidecarStaleLeafDue, true, lastChange)
	view.SetLeaf(groupId, live, 4, sidecar.SidecarStaleLeafLive, true, lastChange)

	if err := view.CommitStaleRemove(t.Context(), groupId, live); err == nil {
		t.Error("committed a live leaf's Remove")
	}
	if err := view.CommitStaleRemove(t.Context(), groupId, due); err != nil {
		t.Fatal(err)
	}
	leaves, err := view.StaleLeaves(t.Context(), []sidecar.Id{due, live})
	if err != nil || len(leaves) != 2 {
		t.Fatalf("%d leaves: %v", len(leaves), err)
	}
	for _, leaf := range leaves {
		if leaf.WorkerId == due && (leaf.State != sidecar.SidecarStaleLeafRemoved || leaf.Epoch != 5) {
			t.Errorf("the committed leaf %+v", leaf)
		}
	}
	if commits := view.Commits(); len(commits) != 1 || commits[0].WorkerId != due {
		t.Errorf("commits %v", commits)
	}
	view.SetErr(errors.New("gkm unavailable"))
	if _, err := view.StaleLeaves(t.Context(), []sidecar.Id{due}); err == nil {
		t.Error("no error while set")
	}
}
