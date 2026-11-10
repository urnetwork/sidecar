//go:build sidecar_testhooks

// EVS2-M10-07's barrier cases: a drop mark survives a path-epoch copy and a fold carrying it while sources stand at
// each barrier of either, held in the source copy or the current one, never in neither.

package evsservice

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The drop marks a path's copies hold, in the epochs given, absent copies skipped.
func dropMarksHeld(t *testing.T, read func(epoch uint64) *EvsEntryRead, epochs ...uint64) []*protocol.EvsDropMark {
	t.Helper()
	marks := []*protocol.EvsDropMark{}
	for _, epoch := range epochs {
		if held := read(epoch); !held.Absent() && held.Entry.GetDropMark() != nil {
			marks = append(marks, held.Entry.GetDropMark())
		}
	}
	return marks
}

// §11.6's copy row: at each of the copy's barriers, before and after its move's PUT, the path's drop mark stands in
// its source copy or its new one, and at the end in the new one alone.
func TestFormat2DropMarkSurvivesACopyAtEachBarrier(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.committedEpochTwo()
	dropped := format2PlantedEntry(t, "a", 2, 2, 2)
	replantEntry(fixture, 1, dropped, EvsEntryStateValue{}, "a")
	read := func(epoch uint64) *EvsEntryRead {
		if epoch == 1 {
			return fixture.entryAt(1, "a")
		}
		return fixture.entryAt(2, "epoch 2", "a")
	}
	refKey := barrierRefKey(fixture.check.repoId, fixture.check.refId)
	names := []string{}
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		if key != refKey || (name != BarrierCopyMoveBefore && name != BarrierCopyMoveAfter) {
			return
		}
		names = append(names, name)
		marks := dropMarksHeld(t, read, 1, 2)
		if len(marks) == 0 || !proto.Equal(marks[0], dropped.GetDropMark()) {
			t.Errorf("at %s the mark is held as %v", name, marks)
		}
	}})
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })
	result, err := RunPathEpochCopy(fixture.ctx, fixture.host.ServiceHost(), nil, fixture.copyArgs(2))
	if err != nil || !result.SourcesDropped {
		t.Fatalf("result %+v %v", result, err)
	}
	if !slices.Contains(names, BarrierCopyMoveBefore) || !slices.Contains(names, BarrierCopyMoveAfter) {
		t.Fatalf("barriers met: %v", names)
	}
	if marks := dropMarksHeld(t, read, 1, 2); len(marks) != 1 || !read(1).Absent() || !proto.Equal(marks[0], dropped.GetDropMark()) {
		t.Fatalf("after the copy: %v", marks)
	}
}

// §11.7's epochs row: a fold that carries a dropped path from its source, writing its next version, holds the mark in
// the source copy or the current one at each of its barriers, the entry write's and the source delete's, and in the
// current one alone once its range is folded.
func TestFormat2DropMarkSurvivesAFoldCarryAtEachBarrier(t *testing.T) {
	world, _ := newFormat2World(t)
	x, x2 := worldPath("x"), worldPath("x2")
	world.pushFormat2(&format2Push{changes: []*format2Change{versioned(&worldChange{path: x, version: 1})}})
	dropId := testId("drop")
	world.fold(world.pushFormat2(format2DropPush(dropId, x, 1, 1)))
	world.cutOverToEpochTwo()
	world.pushFormat2(&format2Push{changes: []*format2Change{versioned(&worldChange{path: x2, base: 2, version: 3, sourcePaths: world.sourceOf(1, x)})}})
	read := func(epoch uint64) *EvsEntryRead {
		path := x2
		if epoch == 1 {
			path = x
		}
		held, err := ReadEntry(world.ctx, world.cluster, world.repoId, world.refId, epoch, path, 0)
		if err != nil {
			t.Fatal(err)
		}
		return held
	}
	refKey := barrierRefKey(world.repoId, world.refId)
	names := []string{}
	watched := []string{BarrierFoldEntryWriteBefore, BarrierFoldEntryWriteAfter, BarrierFoldSourceDeleteBefore, BarrierFoldSourceDeleteAfter}
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		if key != refKey || !slices.Contains(watched, name) {
			return
		}
		names = append(names, name)
		if marks := dropMarksHeld(t, read, 1, 2); len(marks) == 0 || !hasDropMark(&protocol.EvsIndexEntry{DropMark: marks[0]}, dropId, 2) {
			t.Errorf("at %s the mark is held as %v", name, marks)
		}
	}})
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })
	world.foldBy(world.folder)
	for _, name := range watched {
		if !slices.Contains(names, name) {
			t.Fatalf("barriers met: %v", names)
		}
	}
	if !read(1).Absent() || !hasDropMark(read(2).Entry, dropId, 2) {
		t.Fatalf("after the fold: source %v, current %v", read(1).Entry, read(2).Entry)
	}
}
