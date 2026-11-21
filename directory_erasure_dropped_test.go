//go:build !sidecar_http && !ios_extension

// Another erasure's CUT between the directory's CUT of a document into a complete erasure and that ref's rewrite
// (QD-1160; §11.12's cut and reconcile rows, §16.11's Erasure and removal block, DESIGN-DETAILS 15.2.10; FI-19): the
// 30-day sweep's CUT of a later-signed card joins the erasure's entry and keeps its epoch, so another directory admin's
// CUT, reading the erasure complete by its newest ERASE, drops it from the cards ref's set, and the rewrite would list
// nothing and leave the card's index slot under its live key, no longer masked. The directory CUTs the same document
// again, which adds the entry back at the head's epoch, and rewrites again, so the slot ends rewritten under a fresh
// key; dropped a second time, the document goes back uncut in the ledger and the next sync cuts and rewrites it, as at
// the first drop where DroppedCutCount is zero; a kill between the CUT and the rewrite leaves the document in the
// ledger, so the rewrite of the next sync CUTs it again; and an erasure an ERASE opened after the dropping CUT read it
// complete, which the rewrite then finds no CUT of, reads the same. FI-19's index and keys clauses on both refs after
// each step. Both index refs are the index's own erasers on its in-memory fake with one erasure ref between them
// (directory_erasure_after_cut_export_test.go), as in QD-1158's tests (directory_erasure_after_cut_test.go), the cards
// ref's eraser hooked where the other device's push lands.

package sidecar_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
)

// What the hooked cards ref eraser of a device runs: after each CUT of its that commits, another device's push
// landing before the rewrite that follows it; and the failure its next rewrite answers, as a kill between them.
type testDroppedHooks struct {
	afterCut    func(args *sidecar.IndexCutArgs)
	failRewrite error
}

// The cards ref's eraser of one call, hooked.
type testDroppedIndex struct {
	sidecar.DirectoryErasureIndex
	hooks *testDroppedHooks
}

func (self *testDroppedIndex) Cut(ctx context.Context, args *sidecar.IndexCutArgs) (*sidecar.IndexCutResult, error) {
	result, err := self.DirectoryErasureIndex.Cut(ctx, args)
	if err == nil && self.hooks.afterCut != nil {
		self.hooks.afterCut(args)
	}
	return result, err
}

func (self *testDroppedIndex) Rewrite(ctx context.Context, args *sidecar.IndexRewriteArgs) (*sidecar.IndexRewriteResult, error) {
	if err := self.hooks.failRewrite; err != nil {
		self.hooks.failRewrite = nil
		return nil, err
	}
	return self.DirectoryErasureIndex.Rewrite(ctx, args)
}

// The model's reach with both index refs on the fake, the cards ref's eraser hooked.
type testDroppedClient struct {
	*testErasureRefsClient
	hooks *testDroppedHooks
}

func (self *testDroppedClient) CardsIndex(ctx context.Context, repoId sidecar.Id) (sidecar.DirectoryErasureIndex, error) {
	index, err := self.testErasureRefsClient.CardsIndex(ctx, repoId)
	if err != nil {
		return nil, err
	}
	return &testDroppedIndex{DirectoryErasureIndex: index, hooks: self.hooks}, nil
}

// A revocation completed and then a later-signed card: the daemon's card names the repo again at version 3, its
// document entered in the cards ref's index, which no CUT of the erasure lists yet. Another directory admin's device,
// otherId, may CUT on both refs.
type testDroppedSeed struct {
	*testErasureSeed
	admin     *testDirectoryDevice
	refs      *sidecar.DirectoryErasureTestRefs
	runner    *sidecar.DirectoryErasureRunner
	hooks     *testDroppedHooks
	otherId   sidecar.Id
	requestId sidecar.Id
	cardPath  string
}

func newTestDroppedSeed(t *testing.T) *testDroppedSeed {
	t.Helper()
	return newTestDroppedSeedWith(t, nil)
}

// newTestDroppedSeed with its runner on settings, nil for the defaults.
func newTestDroppedSeedWith(t *testing.T, settings *sidecar.DirectoryErasureSettings) *testDroppedSeed {
	t.Helper()
	seed, admin, refs, erase := newTestErasureRefsSeed(t)
	hooks := &testDroppedHooks{}
	admin.client.BindErasureFiles(&testDroppedClient{
		testErasureRefsClient: &testErasureRefsClient{
			testErasureClient: &testErasureClient{evs: seed.evs, sidecarId: admin.writer.sidecarId}, refs: refs,
		},
		hooks: hooks,
	})
	otherId := sidecar.NewId()
	refs.Admit(otherId)
	revocation := seed.revoke(t)
	runner, err := sidecar.NewDirectoryErasureRunner(&sidecar.DirectoryErasureRunnerArgs{
		Client: admin.client, Erase: erase, Raise: (&testErasureRaises{}).raise, Random: &testErasureDelay{}, Settings: settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	dropped := &testDroppedSeed{
		testErasureSeed: seed, admin: admin, refs: refs, runner: runner, hooks: hooks, otherId: otherId,
		requestId: revocation.RequestId, cardPath: sidecar.DirectoryCardPath(seed.daemon.writer.sidecarId),
	}
	admin.pass(t, runner)
	seed.writeRun(t, 2, true)
	if files := admin.pass(t, runner).Files[dropped.requestId]; files == nil || !files.Complete {
		t.Fatalf("the revocation's end: %+v", files)
	}
	refs.Sweep()
	seed.writeRun(t, 3, false)
	refs.Enter(sidecar.DirectoryErasureTestCardsRef, seed.daemon.writer.sidecarId, seed.runDocument, 3)
	if readable := refs.Readable(sidecar.DirectoryErasureTestCardsRef, seed.runDocument); len(readable) == 0 {
		t.Fatal("no index file holds the later card's document")
	}
	return dropped
}

// Another directory admin's device's CUT on the cards ref through index, of an erasure of its own listing a document
// no index file holds: as every CUT does, it drops from the set, by raising listed_since, each erasure index reads
// complete.
func (self *testDroppedSeed) otherCut(t *testing.T, index sidecar.DirectoryErasureIndex, label string) *sidecar.IndexCutResult {
	t.Helper()
	key, err := index.DocKey([]byte("a/elsewhere " + label))
	if err != nil {
		t.Fatal(err)
	}
	result, err := index.Cut(t.Context(), &sidecar.IndexCutArgs{
		ErasureId: sidecar.NewId(), Documents: []*sidecar.IndexCutDocument{{Key: key, Version: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Pushed {
		t.Fatalf("the other erasure's CUT pushed nothing: %+v", result)
	}
	return result
}

// The later-signed card's document rewritten out of every index file under a fresh key, the card's other document kept
// there under its new one, and the set listing it again at its version: FI-19's index and keys clauses on both refs.
func (self *testDroppedSeed) slotRewritten(t *testing.T) {
	t.Helper()
	refs := self.refs
	if version := refs.ListedVersion(sidecar.DirectoryErasureTestCardsRef, self.requestId, self.runDocument); version != 3 {
		t.Fatalf("the cards ref's set lists the later card's document at %d", version)
	}
	if readable := refs.Readable(sidecar.DirectoryErasureTestCardsRef, self.runDocument); len(readable) != 0 {
		t.Fatalf("index versions holding the later card's document still open: %v", readable)
	}
	if readable := refs.Readable(sidecar.DirectoryErasureTestCardsRef, []byte("a/another")); len(readable) == 0 {
		t.Fatal("the other document left the cards ref's index")
	}
	if _, _, complete := refs.Erases(self.requestId); complete {
		t.Fatal("the erasure reads complete while the later card waits for its writer")
	}
	refs.Sweep()
}

// Once the card's writer wrote the run private, the next pass's CLOSURE of the card and its ERASE end the erasure.
func (self *testDroppedSeed) ends(t *testing.T) {
	t.Helper()
	self.writeRun(t, 4, true)
	files := self.admin.pass(t, self.runner).Files[self.requestId]
	if files == nil || !slices.Equal(files.ClosedPaths, []string{self.cardPath}) || !files.Complete {
		t.Fatalf("the pass after the later card's rewrite: %+v", files)
	}
	if _, _, complete := self.refs.Erases(self.requestId); !complete {
		t.Fatal("the erasure did not end again")
	}
	if readable := self.evs.readable(t, testErasureProject); len(readable) != 0 {
		t.Fatalf("card versions naming the repo still open: %v", readable)
	}
	self.refs.Sweep()
}

// Another directory admin's CUT lands between the pass's CUT of the later-signed card and the cards ref's rewrite and
// drops the complete erasure from the set: the rewrite says dropped, the pass CUTs the document again, which adds the
// entry back at the head's epoch, the one the other CUT moved it to, and rewrites the slot holding it under a fresh
// key while the card waits for its writer, whose private write then ends the erasure. Before QD-1160 the rewrite read
// the dropped erasure done and the slot kept the document under its live key, unlisted, so it could come back in
// search.
func TestDirectoryFormat2CutDroppedBeforeItsRewriteIsCutAgain(t *testing.T) {
	seed := newTestDroppedSeed(t)
	refs := seed.refs
	if !refs.Lists(sidecar.DirectoryErasureTestCardsRef, seed.requestId) {
		t.Fatal("the complete erasure is off the cards ref's set before the pass")
	}
	firstEpoch := refs.ListedEpoch(sidecar.DirectoryErasureTestCardsRef, seed.requestId)
	var joinedEpoch uint64
	var dropping *sidecar.IndexCutResult
	seed.hooks.afterCut = func(args *sidecar.IndexCutArgs) {
		if args.ErasureId != seed.requestId || dropping != nil {
			return
		}
		joinedEpoch = refs.ListedEpoch(sidecar.DirectoryErasureTestCardsRef, seed.requestId)
		dropping = seed.otherCut(t, refs.Open(sidecar.DirectoryErasureTestCardsRef, seed.otherId), "first")
		if refs.Lists(sidecar.DirectoryErasureTestCardsRef, seed.requestId) {
			t.Fatal("the other erasure's CUT kept the complete erasure in the set")
		}
	}

	files := seed.admin.pass(t, seed.runner).Files[seed.requestId]
	if dropping == nil || dropping.DroppedCount != 1 {
		t.Fatalf("the other erasure's CUT: %+v", dropping)
	}
	if files == nil || files.CutCount != 2 || files.IndexPairCount == 0 || files.IndexWaiting || files.Complete ||
		!slices.Equal(files.WaitingPaths, []string{seed.cardPath}) || len(files.ClosedPaths) != 0 {
		t.Fatalf("the pass whose CUT the other erasure's dropped: %+v", files)
	}
	// the pass's CUT joined the entry at its first epoch, and the CUT again added it back at the one the other moved
	// the head to
	if epoch := refs.ListedEpoch(sidecar.DirectoryErasureTestCardsRef, seed.requestId); joinedEpoch != firstEpoch ||
		dropping.Version <= joinedEpoch || epoch != dropping.Version {
		t.Fatalf("the entry's epoch: %d first, %d when joined, %d after the CUT again, the other CUT at %d",
			firstEpoch, joinedEpoch, epoch, dropping.Version)
	}
	seed.slotRewritten(t)

	// a sync with nothing new sends nothing
	if files := seed.admin.pass(t, seed.runner).Files[seed.requestId]; files != nil && (files.CutCount != 0 || files.IndexPairCount != 0) {
		t.Fatalf("the pass after: %+v", files)
	}
	seed.ends(t)
}

// Another directory admin's CUT drops the erasure after the pass's CUT and again after its CUT again: the second
// rewrite says dropped too, so the document goes back uncut in the ledger, the call waits and nothing says complete,
// the slot still holding the document unlisted; the next sync cuts it again, adding the entry back, and its rewrite
// takes the slot under a fresh key.
func TestDirectoryFormat2CutDroppedTwiceGoesBackUncutForTheNextSync(t *testing.T) {
	seed := newTestDroppedSeed(t)
	refs := seed.refs
	drops := 0
	seed.hooks.afterCut = func(args *sidecar.IndexCutArgs) {
		if args.ErasureId != seed.requestId || 2 <= drops {
			return
		}
		drops += 1
		seed.otherCut(t, refs.Open(sidecar.DirectoryErasureTestCardsRef, seed.otherId), fmt.Sprintf("drop %d", drops))
	}

	files := seed.admin.pass(t, seed.runner).Files[seed.requestId]
	if drops != 2 || files == nil || files.CutCount != 2 || files.IndexPairCount != 0 || !files.IndexWaiting || files.Complete {
		t.Fatalf("the pass dropped twice: %d drops, files %+v", drops, files)
	}
	if refs.Lists(sidecar.DirectoryErasureTestCardsRef, seed.requestId) {
		t.Fatal("the set lists the erasure after its second drop")
	}
	if readable := refs.Readable(sidecar.DirectoryErasureTestCardsRef, seed.runDocument); len(readable) == 0 {
		t.Fatal("a rewrite took the later card's document while its erasure was off the set")
	}
	refs.Sweep()

	files = seed.admin.pass(t, seed.runner).Files[seed.requestId]
	if files == nil || files.CutCount != 1 || files.IndexPairCount == 0 || files.IndexWaiting || files.Complete {
		t.Fatalf("the next sync's pass: %+v", files)
	}
	seed.slotRewritten(t)
	seed.ends(t)
}

// With DroppedCutCount zero the first drop already puts the document back uncut: the pass CUTs nothing again and
// waits, saying nothing complete, and the next sync's CUT and rewrite take the slot.
func TestDirectoryFormat2CutDroppedWithNoCutAgainGoesBackUncutAtOnce(t *testing.T) {
	settings := sidecar.DefaultDirectoryErasureSettings()
	settings.DroppedCutCount = 0
	seed := newTestDroppedSeedWith(t, settings)
	refs := seed.refs
	drops := 0
	seed.hooks.afterCut = func(args *sidecar.IndexCutArgs) {
		if args.ErasureId != seed.requestId || 0 < drops {
			return
		}
		drops += 1
		seed.otherCut(t, refs.Open(sidecar.DirectoryErasureTestCardsRef, seed.otherId), "once")
	}

	files := seed.admin.pass(t, seed.runner).Files[seed.requestId]
	if drops != 1 || files == nil || files.CutCount != 1 || files.IndexPairCount != 0 || !files.IndexWaiting || files.Complete {
		t.Fatalf("the pass dropped with no CUT again: %d drops, files %+v", drops, files)
	}
	if refs.Lists(sidecar.DirectoryErasureTestCardsRef, seed.requestId) {
		t.Fatal("the set lists the erasure after its drop")
	}
	refs.Sweep()

	files = seed.admin.pass(t, seed.runner).Files[seed.requestId]
	if files == nil || files.CutCount != 1 || files.IndexPairCount == 0 || files.IndexWaiting || files.Complete {
		t.Fatalf("the next sync's pass: %+v", files)
	}
	seed.slotRewritten(t)
	seed.ends(t)
}

// A kill between the pass's CUT of the later-signed card and the cards ref's rewrite, then another directory admin's
// CUT that drops the erasure: the next pass finds nothing uncut and the rewrite owed, which says dropped, so it CUTs
// again the document the ledger holds for that rewrite and rewrites the slot under a fresh key.
func TestDirectoryFormat2CutDroppedAfterAKillBeforeItsRewriteIsCutAgain(t *testing.T) {
	seed := newTestDroppedSeed(t)
	refs := seed.refs
	crash := errors.New("the device stopped")
	seed.hooks.failRewrite = crash
	seed.admin.mustSync(t)
	if _, err := seed.runner.Pass(t.Context()); !errors.Is(err, crash) {
		t.Fatalf("the pass killed before its rewrite: %v", err)
	}
	if version := refs.ListedVersion(sidecar.DirectoryErasureTestCardsRef, seed.requestId, seed.runDocument); version != 3 {
		t.Fatalf("the killed pass's CUT lists the later card's document at %d", version)
	}
	dropping := seed.otherCut(t, refs.Open(sidecar.DirectoryErasureTestCardsRef, seed.otherId), "after the kill")
	if dropping.DroppedCount != 1 || refs.Lists(sidecar.DirectoryErasureTestCardsRef, seed.requestId) {
		t.Fatalf("the other erasure's CUT kept the complete erasure in the set: %+v", dropping)
	}

	files := seed.admin.pass(t, seed.runner).Files[seed.requestId]
	if files == nil || files.CutCount != 1 || files.IndexPairCount == 0 || files.IndexWaiting || files.Complete {
		t.Fatalf("the pass after the kill and the drop: %+v", files)
	}
	if epoch := refs.ListedEpoch(sidecar.DirectoryErasureTestCardsRef, seed.requestId); epoch != dropping.Version {
		t.Fatalf("the entry added back at %d, the other CUT at %d", epoch, dropping.Version)
	}
	seed.slotRewritten(t)
	seed.ends(t)
}

// Another directory admin's CUT whose read of the erasure ref came before an ERASE opened the erasure again drops it
// between the pass's CUT and the cards ref's rewrite: the rewrite, reading it open, finds no CUT of it on the ref, which
// after this device's own CUT there reads as the drop it is, so the pass CUTs the document again and the rewrite takes
// the slot.
func TestDirectoryFormat2CutDroppedOnAStaleReadBeforeItsRewriteIsCutAgain(t *testing.T) {
	seed := newTestDroppedSeed(t)
	refs := seed.refs
	dropped := false
	seed.hooks.afterCut = func(args *sidecar.IndexCutArgs) {
		if args.ErasureId != seed.requestId || dropped {
			return
		}
		dropped = true
		// the ERASE that opens the erasure again, as another runner's relisted pair's, lands after the other CUT's read
		refs.NoteErase(&sidecar.EvsEraseArgs{ErasureId: seed.requestId, Keys: []*sidecar.EvsErasedKey{{SlotId: sidecar.NewId()}}})
		if _, _, complete := refs.Erases(seed.requestId); complete {
			t.Fatal("the erasure reads complete after the ERASE that opens it")
		}
		seed.otherCut(t, refs.OpenStale(sidecar.DirectoryErasureTestCardsRef, seed.otherId, seed.requestId), "stale")
		if refs.Lists(sidecar.DirectoryErasureTestCardsRef, seed.requestId) {
			t.Fatal("the stale CUT kept the erasure in the set")
		}
	}

	files := seed.admin.pass(t, seed.runner).Files[seed.requestId]
	if !dropped || files == nil || files.CutCount != 2 || files.IndexPairCount == 0 || files.IndexWaiting || files.Complete {
		t.Fatalf("the pass whose CUT the stale CUT dropped: %+v", files)
	}
	seed.slotRewritten(t)
	seed.ends(t)
}
