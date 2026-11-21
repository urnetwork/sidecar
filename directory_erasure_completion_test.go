//go:build !sidecar_http && !ios_extension

// A directory erasure that no ERASE with a key is left to say complete (QD-1132, QD-1137; §11.12's reconcile row,
// §11.14's cut row): format 2's half asks the last index ref a CUT of it stands on to end it, so a rewrite that finds
// no file holding a listed version ends it by a completion ERASE, and the next CUT, another erasure's, drops it from
// the ref's erasure set. The cards ref is directory_erasure_index_test.go's model, the cards ref's index the index's own
// eraser on its in-memory fake (directory_erasure_completion_export_test.go), told of each ERASE of the cards' keys, and
// ur/index the model's, which no CUT of these erasures reaches.

package sidecar_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The model's reach, with the cards ref's index on the index's fake: sidecar.DirectoryErasureFiles.
type testErasureCompletionClient struct {
	*testErasureClient
	index *sidecar.DirectoryErasureTestIndex
}

func (self *testErasureCompletionClient) CardsIndex(ctx context.Context, repoId sidecar.Id) (sidecar.DirectoryErasureIndex, error) {
	return self.index.Open(self.sidecarId), nil
}

func (self *testErasureCompletionClient) EraseCardKeys(ctx context.Context, repoId sidecar.Id, args *sidecar.EvsEraseArgs) error {
	if err := self.testErasureClient.EraseCardKeys(ctx, repoId, args); err != nil {
		return err
	}
	self.index.NoteErase(args)
	return nil
}

// Binds device's format-2 erasers with the cards ref's index on the fake.
func (self *testErasureEvs) bindCompletion(device *testDirectoryDevice, index *sidecar.DirectoryErasureTestIndex) {
	device.client.BindErasureFiles(&testErasureCompletionClient{
		testErasureClient: &testErasureClient{evs: self, sidecarId: device.writer.sidecarId}, index: index,
	})
}

// A format-2 directory with a writer's card holding two runs, neither of whose documents any file of the cards ref's
// index holds: the index never took them in.
type testErasureCompletionSeed struct {
	world    *testDirectoryWorld
	evs      *testErasureEvs
	device   *testDirectoryDevice
	memberId sidecar.Id
	erasedId sidecar.Id
	keptId   sidecar.Id
}

func newTestErasureCompletionSeed(t *testing.T) *testErasureCompletionSeed {
	t.Helper()
	world, evs := newTestErasureWorld(t)
	world.cards.RaiseFormat(world.directoryId)
	seed := &testErasureCompletionSeed{world: world, evs: evs, memberId: sidecar.NewId(), erasedId: sidecar.NewId(), keptId: sidecar.NewId()}
	seed.device = world.device(world.memberWriter(seed.memberId))
	world.publish()
	seed.device.writeCard(t, seed.item(seed.erasedId), seed.item(seed.keptId))
	return seed
}

// The writer's run item id, at version 1.
func (self *testErasureCompletionSeed) item(announcementId sidecar.Id) *protocol.Announcement {
	return testRunItem(self.device.writer.sidecarId, &self.memberId, announcementId, 1, self.world.clock.Now().UnixMilli())
}

// An admin's erasure of the writer's run whose rewrite of the cards ref's index is unproven, as where the store could
// not walk the index's history whole: the card goes by moderation's removal and its keys by an ERASE, which says
// nothing complete, so the erasure waits listed in the set.
func (self *testErasureCompletionSeed) eraseUnproven(t *testing.T, admin *testDirectoryDevice, index *sidecar.DirectoryErasureTestIndex) *sidecar.DirectoryEraseResult {
	t.Helper()
	admin.mustSync(t)
	index.SetHistoryWhole(false)
	erased, err := admin.client.Erase(t.Context(), &sidecar.DirectoryEraseArgs{Id: self.erasedId, Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	cardPath := sidecar.DirectoryCardPath(self.device.writer.sidecarId)
	if erased.Files == nil || erased.Files.Complete || !erased.Files.IndexWaiting || !slices.Equal(erased.Files.RemovedPaths, []string{cardPath}) {
		t.Fatalf("the unproven erasure's files: %+v", erased.Files)
	}
	if count, completions, complete := index.Erases(erased.ErasureId); count != 1 || completions != 0 || complete || !index.Lists(erased.ErasureId) {
		t.Fatalf("the unproven erasure: %d ERASEs, %d completions, complete %t, listed %t", count, completions, complete, index.Lists(erased.ErasureId))
	}
	index.SetHistoryWhole(true)
	return erased
}

// The writer's card back with its kept run, and the admin's erasure of that run: another erasure, whose CUT on the cards
// ref's index drops each complete erasure from the set.
func (self *testErasureCompletionSeed) eraseKept(t *testing.T, admin *testDirectoryDevice) *sidecar.DirectoryEraseResult {
	t.Helper()
	self.world.clock.Advance(time.Minute)
	self.world.publish()
	self.device.writeCard(t, self.item(self.keptId))
	admin.mustSync(t)
	erased, err := admin.client.Erase(t.Context(), &sidecar.DirectoryEraseArgs{Id: self.keptId, Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	return erased
}

// The erasure's own device resumes it once the history walks whole: its rewrite, the erasure's last, finds no file to
// rewrite and ends it by a completion ERASE naming the card's key, and the next CUT drops it from the set.
func TestDirectoryFormat2ErasureWhoseRewriteFindsNoFileEndsByACompletion(t *testing.T) {
	seed := newTestErasureCompletionSeed(t)
	admin := seed.evs.adminDevice(t)
	index := sidecar.NewDirectoryErasureTestIndex(t, admin.writer.sidecarId)
	seed.evs.bindCompletion(admin, index)
	first := seed.eraseUnproven(t, admin, index)

	runner, _ := admin.runner(t, 0, nil)
	admin.pass(t, runner)
	if count, completions, complete := index.Erases(first.ErasureId); count != 2 || completions != 1 || !complete {
		t.Fatalf("the resumed erasure: %d ERASEs, %d completions, complete %t", count, completions, complete)
	}
	if !index.Lists(first.ErasureId) {
		t.Fatal("the erasure left the set before any CUT")
	}
	second := seed.eraseKept(t, admin)
	if index.Lists(first.ErasureId) || !index.Lists(second.ErasureId) {
		t.Fatalf("after the next CUT the set lists the completed erasure %t, the new one %t", index.Lists(first.ErasureId), index.Lists(second.ErasureId))
	}
	// a pass with nothing left sends nothing more
	count, _, _ := index.Erases(first.ErasureId)
	admin.pass(t, runner)
	if again, _, _ := index.Erases(first.ErasureId); again != count {
		t.Fatalf("a later pass sent %d ERASEs more", again-count)
	}
}

// Another device takes the erasure up where its eraser began it, as a runner takes up a request another runner's ERASE
// names: both refs read owed, the cards ref's rewrite runs first without complete, and ur/index holds no CUT of it. The
// cards ref's rewrite, the last a CUT of it stands on, is asked again to end it, and ends it by a completion ERASE.
func TestDirectoryFormat2ErasureTakenUpEndsOnTheLastRefItIsCutOn(t *testing.T) {
	seed := newTestErasureCompletionSeed(t)
	eraser := seed.evs.adminDevice(t)
	other := seed.evs.adminDevice(t)
	index := sidecar.NewDirectoryErasureTestIndex(t, eraser.writer.sidecarId, other.writer.sidecarId)
	seed.evs.bindCompletion(eraser, index)
	seed.evs.bindCompletion(other, index)
	first := seed.eraseUnproven(t, eraser, index)

	other.mustSync(t)
	files, err := other.client.EraseBegunFilesForTest(t.Context(), first.ErasureId, first.Reason)
	if err != nil {
		t.Fatal(err)
	}
	if !files.Complete || files.IndexWaiting || files.IndexPairCount != 0 {
		t.Fatalf("the taken-up erasure's files: %+v", files)
	}
	if count, completions, complete := index.Erases(first.ErasureId); count != 2 || completions != 1 || !complete {
		t.Fatalf("the taken-up erasure: %d ERASEs, %d completions, complete %t", count, completions, complete)
	}
	second := seed.eraseKept(t, other)
	if index.Lists(first.ErasureId) || !index.Lists(second.ErasureId) {
		t.Fatalf("after the next CUT the set lists the completed erasure %t, the new one %t", index.Lists(first.ErasureId), index.Lists(second.ErasureId))
	}
}

// A kill between a revocation's last CLOSURE and that CLOSURE's ERASE: the eraser's device, started again, erases the
// orphaned CLOSURE's keys first, and with nothing else of the erasure owed that ERASE says it complete (QD-1132), so
// the erasure ends at once and another device that takes it up after sends nothing. Its ERASE once said nothing
// complete, and the erasure ended unsaid unless another device took it up.
func TestDirectoryFormat2RestartEndsAnErasureByItsOrphanedClosuresErase(t *testing.T) {
	seed := newTestErasureSeed(t)
	evs := seed.evs
	revocation := seed.revoke(t)
	first := evs.adminDevice(t)
	other := evs.adminDevice(t)
	index := sidecar.NewDirectoryErasureTestIndex(t, first.writer.sidecarId, other.writer.sidecarId)
	evs.bindCompletion(first, index)
	evs.bindCompletion(other, index)
	runner, _ := first.runner(t, 0, nil)
	// the first pass closes the repo file and leaves the card that still names the repo waiting for its writer
	first.pass(t, runner)
	if _, _, complete := index.Erases(revocation.RequestId); complete {
		t.Fatal("the erasure reads complete while a card waits for its writer")
	}
	// the writer writes its run private, and the next pass dies between the card's CLOSURE and its ERASE
	seed.writeRun(t, 2, true)
	evs.failEraseCount = 1
	first.mustSync(t)
	if _, err := runner.Pass(t.Context()); err == nil {
		t.Fatal("the pass killed after the card's CLOSURE returned no error")
	}
	count, _, _ := index.Erases(revocation.RequestId)

	restarted := seed.world.restarted(first)
	evs.admit(restarted)
	evs.bindCompletion(restarted, index)
	restartedRunner, _ := restarted.runner(t, 0, nil)
	restarted.pass(t, restartedRunner)
	if after, completions, complete := index.Erases(revocation.RequestId); after != count+1 || completions != 0 || !complete {
		t.Fatalf("after the restart: %d ERASEs more, %d completions, complete %t", after-count, completions, complete)
	}
	if readable := evs.readable(t, testErasureProject); len(readable) != 0 {
		t.Fatalf("card versions naming the repo still open: %v", readable)
	}
	closures, erases, cuts := evs.counts()
	otherRunner, _ := other.runner(t, 0, nil)
	other.pass(t, otherRunner)
	againClosures, againErases, againCuts := evs.counts()
	if again, _, _ := index.Erases(revocation.RequestId); again != count+1 || againClosures != closures || againErases != erases || againCuts != cuts {
		t.Fatalf("the other device sent pushes after the erasure ended: %d ERASEs on the index's ref, %d %d %d, were %d %d %d", again-count-1, againClosures, againErases, againCuts, closures, erases, cuts)
	}
}
