package evsservice

import (
	"testing"

	"github.com/urnetwork/sidecar"
)

// NewestWalked of path at the world's head for a reader pinned at after, its entry read after the head.
func (self *evsWorld) newestWalked(path sidecar.EvsTokenPath, after uint64) *EvsNewest {
	self.t.Helper()
	head, err := self.heads.ReadCluster(self.ctx, self.cluster, self.repoId, self.refId)
	if err != nil {
		self.t.Fatal(err)
	}
	read, err := ReadEntry(self.ctx, self.cluster, self.repoId, self.refId, 1, path, head.Head.GetFoldedThrough())
	if err != nil {
		self.t.Fatal(err)
	}
	newest, err := NewestWalked(self.ctx, read, head.Head, NewRecordPushSource(NewRecordCache(self.settings), nil, self.cluster, self.repoId, self.refId), after)
	if err != nil {
		self.t.Fatalf("newest walked: %v", err)
	}
	return newest
}

// Deletes path's entry, as a marker's collection does.
func (self *evsWorld) deleteEntry(path sidecar.EvsTokenPath) {
	self.t.Helper()
	if err := self.cluster.Delete(self.paidCtx, IndexEntryKey(self.repoId, self.refId, 1, path)); err != nil {
		self.t.Fatal(err)
	}
}

// Whether newest names a path neither standing nor removed.
func plainAbsent(newest *EvsNewest) bool {
	return !newest.Exists && newest.RemovalVersion == 0 && newest.CommitVersion == 0 && !newest.Collected
}

// QD-879: a file removed below the horizon whose marker a collection took reads as never written by the rule, and
// as its removal, from the window, to a reader pinned below it; a reader pinned at or past it reads it absent, and
// so does every reader once the window pages the removal out. A re-creation reads as any version.
func TestNewestWalkedServesARemovalWhoseMarkerACollectionTook(t *testing.T) {
	world := newEvsWorld(t)
	file := worldPath("x")
	world.push(&worldChange{path: file, version: 1})
	world.push(&worldChange{path: file, base: 1, version: 2})
	world.push(&worldChange{path: file, base: 2})
	world.push(&worldChange{path: worldPath("g"), version: 4})
	world.fold(4)
	marked := world.requireNewest(file)
	if marked.Marker == nil || marked.RemovalVersion != 3 || marked.CommitVersion != 3 {
		t.Fatalf("the marker %+v", marked)
	}
	// its marker stands: a walk reads the rule's answer
	if walked := world.newestWalked(file, 0); walked.Marker == nil || walked.Collected {
		t.Fatalf("under its marker %+v", walked)
	}
	world.deleteEntry(file)
	if newest, err := world.newest(file); err != nil || !plainAbsent(newest) {
		t.Fatalf("the rule after the collection %+v %v", newest, err)
	}
	for _, after := range []uint64{0, 1, 2} {
		walked := world.newestWalked(file, after)
		if walked.Exists || !walked.Collected || walked.FromWindow || walked.RemovedByPrefix || walked.CommitVersion != 3 ||
			walked.RemovalVersion != marked.RemovalVersion || walked.PushId != marked.PushId || walked.Change == nil || !walked.Change.Removes() {
			t.Fatalf("pinned at %d: %+v, the marker's %+v", after, walked, marked)
		}
	}
	for _, after := range []uint64{3, 4, 9} {
		if walked := world.newestWalked(file, after); !plainAbsent(walked) {
			t.Fatalf("pinned at %d, past the removal: %+v", after, walked)
		}
	}
	// a path never written, and one whose version the entry lost: neither is a removal
	if walked := world.newestWalked(worldPath("never"), 0); !plainAbsent(walked) {
		t.Fatalf("a path never written: %+v", walked)
	}
	world.deleteEntry(worldPath("g"))
	if walked := world.newestWalked(worldPath("g"), 0); !plainAbsent(walked) {
		t.Fatalf("a version its entry lost: %+v", walked)
	}
	// re-created past the removal: max(b, m) + 1, and the rule reads the version
	want := ExpectedEntryVersion(0, world.head.Version(), 0)
	if want != ExpectedEntryVersion(0, world.head.Version(), marked.RemovalVersion) {
		t.Fatalf("the creation's version %d moves with the marker", want)
	}
	world.push(&worldChange{path: file, version: want})
	if walked := world.newestWalked(file, 0); !walked.Exists || walked.Version != want || walked.Collected {
		t.Fatalf("re-created: %+v", walked)
	}
	world.fold(5)
	if walked := world.newestWalked(file, 0); !walked.Exists || walked.Version != want || walked.Collected {
		t.Fatalf("re-created and folded: %+v", walked)
	}
}

// The window is all the case reads: once it pages the removing version out, the path reads absent to every reader.
func TestNewestWalkedReadsNoRemovalTheWindowPagedOut(t *testing.T) {
	world := newEvsWorld(t)
	file := worldPath("x")
	world.push(&worldChange{path: file, version: 1})
	world.push(&worldChange{path: file, base: 1})
	world.push(&worldChange{path: worldPath("g"), version: 3})
	world.fold(3)
	world.deleteEntry(file)
	if walked := world.newestWalked(file, 0); !walked.Collected || walked.CommitVersion != 2 || walked.RemovalVersion != 2 {
		t.Fatalf("in the window: %+v", walked)
	}
	world.pageOut(2)
	if walked := world.newestWalked(file, 0); !plainAbsent(walked) {
		t.Fatalf("paged out: %+v", walked)
	}
}

// A removed directory's markers, collected by the real collector: the directory reads as removed from the window, a
// child as removed by its prefix one past the version it held, to a reader whose walk holds that version, and as
// absent to one whose walk holds the prefix's removal alone.
func TestNewestWalkedServesAPrefixRemovalOverAVersionInTheWalk(t *testing.T) {
	world, marked, other := newCollectWorld(t)
	directory, child := marked[0], marked[1]
	before := world.requireNewest(child)
	if before.Marker == nil || before.RemovalVersion != 2 || before.CommitVersion != 2 {
		t.Fatalf("the child's marker %+v", before)
	}
	collector, _ := collectorOf(t, world, nil)
	if result := world.collect(collector); result.MarkerDeletedCount != 3 {
		t.Fatalf("the collection %+v", result)
	}
	world.head, _ = world.heads.ReadCluster(world.ctx, world.cluster, world.repoId, world.refId)
	if newest, err := world.newest(child); err != nil || !plainAbsent(newest) {
		t.Fatalf("the rule after the collection %+v %v", newest, err)
	}
	walked := world.newestWalked(directory, 0)
	if walked.Exists || !walked.Collected || walked.RemovedByPrefix || walked.CommitVersion != 2 || walked.RemovalVersion != 2 {
		t.Fatalf("the directory %+v", walked)
	}
	walked = world.newestWalked(child, 0)
	if walked.Exists || !walked.Collected || !walked.RemovedByPrefix || walked.CommitVersion != 2 ||
		walked.RemovalVersion != before.RemovalVersion || walked.PushId != before.PushId {
		t.Fatalf("the child %+v, its marker's %+v", walked, before)
	}
	// pinned at the child's creation: the walk holds the directory's removal alone, which a path served absent
	// stands through
	if walked := world.newestWalked(child, 1); !plainAbsent(walked) {
		t.Fatalf("the child, pinned at its creation: %+v", walked)
	}
	if walked := world.newestWalked(other, 0); !walked.Exists || walked.Collected {
		t.Fatalf("a standing path %+v", walked)
	}
}

// A path removed and then lying under a removed prefix: the prefix's removal adds none of its own, so the path's own
// removal is what a walk reads.
func TestNewestWalkedReadsAPathsOwnRemovalBelowAPrefixRemoval(t *testing.T) {
	world := newEvsWorld(t)
	directory, child := worldPath("d"), worldPath("d", "x")
	world.push(&worldChange{path: directory, directory: true, version: 1, names: []sidecar.EvsToken{worldToken("x")}}, &worldChange{path: child, version: 1})
	world.push(&worldChange{path: directory, directory: true, base: 1, version: 2, removedTokens: []sidecar.EvsToken{worldToken("x")}}, &worldChange{path: child, base: 1})
	world.push(&worldChange{path: directory, base: 2})
	world.push(&worldChange{path: worldPath("g"), version: 4})
	world.fold(4)
	world.deleteEntry(child)
	walked := world.newestWalked(child, 0)
	if walked.Exists || !walked.Collected || walked.RemovedByPrefix || walked.CommitVersion != 2 || walked.RemovalVersion != 2 {
		t.Fatalf("the child %+v", walked)
	}
	// pinned past its own removal: the prefix's removal alone is no removal of the path
	if walked := world.newestWalked(child, 2); !plainAbsent(walked) {
		t.Fatalf("the child, pinned past its removal: %+v", walked)
	}
}
