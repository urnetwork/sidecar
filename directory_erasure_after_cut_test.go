//go:build !sidecar_http && !ios_extension

// A format-2 directory erasure that holds M6 announce entries beside its copies on format 2's carriers (QD-1158;
// DESIGN-DETAILS 15.2.10's step 2, §11.12's reconcile and directory rows, §11.14's cut and erase rows, §16.11's
// Erasure and removal block; FI-19): the entries' ERASEs, the record's, say nothing complete, so no ERASE of the
// erasure says complete before its CUT, and both index refs' files holding its documents are rewritten under fresh
// keys, for a directory admin's erase as for a revocation; and a later CUT that adds a document to the erasure once it
// is complete, the 30-day sweep's later-signed card, has the index slot holding it rewritten under a fresh key while
// the card waits for its writer, the erasure ending again with the card's CLOSURE. FI-19's index and keys clauses after
// each. The cards ref is directory_erasure_index_test.go's model; both index refs are the index's own erasers on its
// in-memory fake with one erasure ref between them (directory_erasure_after_cut_export_test.go), which the record's
// ERASEs and the cards' are told of in order, as evs's erasure ref holds them.

package sidecar_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
)

// The model's reach with both of the directory's index refs on the fake: sidecar.DirectoryErasureFiles.
type testErasureRefsClient struct {
	*testErasureClient
	refs *sidecar.DirectoryErasureTestRefs
}

func (self *testErasureRefsClient) CardsIndex(ctx context.Context, repoId sidecar.Id) (sidecar.DirectoryErasureIndex, error) {
	return self.refs.Open(sidecar.DirectoryErasureTestCardsRef, self.sidecarId), nil
}

func (self *testErasureRefsClient) StreamsIndex(ctx context.Context, repoId sidecar.Id) (sidecar.DirectoryErasureIndex, error) {
	return self.refs.Open(sidecar.DirectoryErasureTestStreamsRef, self.sidecarId), nil
}

func (self *testErasureRefsClient) EraseCardKeys(ctx context.Context, repoId sidecar.Id, args *sidecar.EvsEraseArgs) error {
	if err := self.testErasureClient.EraseCardKeys(ctx, repoId, args); err != nil {
		return err
	}
	self.refs.NoteErase(args)
	return nil
}

// Binds device's erasers to the model with both index refs on refs, the record's ERASEs told to refs' erasure ref as
// each of the record's erasures returns, before anything of format 2's half goes: the eraser a runner of the device
// takes.
func (self *testErasureEvs) bindRefs(device *testDirectoryDevice, refs *sidecar.DirectoryErasureTestRefs) sidecar.DirectoryEraseFunction {
	world := self.world
	erase := func(ctx context.Context, args *sidecar.RecordEraseArgs) (*sidecar.RecordEraseResult, error) {
		result, err := device.record.Eraser().Erase(ctx, args)
		erasures, readErr := world.streams.For(world.readerId).ReadErasures(ctx, world.directoryId, 0)
		if readErr != nil {
			return result, errors.Join(err, readErr)
		}
		refs.NoteStreamErasures(erasures)
		return result, err
	}
	device.client.BindEraser(erase)
	device.client.BindErasureFiles(&testErasureRefsClient{
		testErasureClient: &testErasureClient{evs: self, sidecarId: device.writer.sidecarId}, refs: refs,
	})
	return erase
}

// A runner on device erasing through erase, with no wait.
func testRefsRunner(t *testing.T, device *testDirectoryDevice, erase sidecar.DirectoryEraseFunction) *sidecar.DirectoryErasureRunner {
	t.Helper()
	runner, err := sidecar.NewDirectoryErasureRunner(&sidecar.DirectoryErasureRunnerArgs{
		Client: device.client, Erase: erase, Raise: (&testErasureRaises{}).raise, Random: &testErasureDelay{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

// The record's ERASEs of the directory that name erasureId and say complete.
func (self *testDirectoryWorld) completeStreamErasures(t *testing.T, erasureId sidecar.Id) int {
	t.Helper()
	erasures, err := self.streams.For(self.readerId).ReadErasures(t.Context(), self.directoryId, 0)
	if err != nil {
		t.Fatal(err)
	}
	named, complete := 0, 0
	for _, erasure := range erasures {
		if erasure.ErasureId != erasureId {
			continue
		}
		named += 1
		if erasure.Complete {
			complete += 1
		}
	}
	if named == 0 {
		t.Fatalf("no ERASE of the record names %s", erasureId)
	}
	return complete
}

// newTestErasureSeed's revoke world with both index refs on the fake, its documents entered as the files' pushes and
// the announce entry's companion push left them, and a directory admin's device bound to them, with its eraser.
func newTestErasureRefsSeed(t *testing.T) (*testErasureSeed, *testDirectoryDevice, *sidecar.DirectoryErasureTestRefs, sidecar.DirectoryEraseFunction) {
	t.Helper()
	seed := newTestErasureSeed(t)
	admin := seed.evs.adminDevice(t)
	refs := sidecar.NewDirectoryErasureTestRefs(t, admin.writer.sidecarId)
	ownerId, daemonId := seed.owner.writer.sidecarId, seed.daemon.writer.sidecarId
	refs.Enter(sidecar.DirectoryErasureTestCardsRef, ownerId, seed.repoDocument, 2)
	refs.Enter(sidecar.DirectoryErasureTestCardsRef, daemonId, seed.runDocument, 1)
	refs.Enter(sidecar.DirectoryErasureTestCardsRef, daemonId, []byte("a/another"), 1)
	refs.Enter(sidecar.DirectoryErasureTestStreamsRef, ownerId, seed.repoDocument, 1)
	return seed, admin, refs, seed.evs.bindRefs(admin, refs)
}

// A revocation of a repo announced by an M6 entry and moved onto its r/ file: the runner's first pass erases the entry,
// whose ERASE says nothing complete, then cuts both refs, rewrites both refs' index files holding the documents and
// the repo file, and leaves the card that still names the repo waiting, nothing saying complete; once the card's writer
// wrote the run private the next pass rewrites the card and its ERASE ends the erasure. No ERASE of the erasure says
// complete before its CUT. Before QD-1158 the entry's ERASE said complete, so both refs' rewrites read the erasure done
// and rewrote nothing.
func TestDirectoryFormat2RevokeOfAnnounceEntriesAndCopiesSaysNothingCompleteBeforeItsCut(t *testing.T) {
	seed, admin, refs, erase := newTestErasureRefsSeed(t)
	world, evs := seed.world, seed.evs
	revocation := seed.revoke(t)
	runner := testRefsRunner(t, admin, erase)
	requestId := revocation.RequestId
	repoPath := sidecar.DirectoryRepoPath(seed.repoId)
	cardPath := sidecar.DirectoryCardPath(seed.daemon.writer.sidecarId)

	pass := admin.pass(t, runner)
	files := pass.Files[requestId]
	if len(pass.Erased[requestId]) != 1 || files == nil {
		t.Fatalf("the first pass: erased %v, files %+v", pass.Erased, files)
	}
	if !slices.Equal(files.ClosedPaths, []string{repoPath}) || !slices.Equal(files.WaitingPaths, []string{cardPath}) || files.CutCount != 2 ||
		files.IndexPairCount == 0 || files.Complete {
		t.Fatalf("the first pass's files: %+v", files)
	}
	if complete := world.completeStreamErasures(t, requestId); complete != 0 {
		t.Fatalf("%d of the announce entries' ERASEs said complete", complete)
	}
	if refs.CompleteBeforeCut(requestId) {
		t.Fatal("an ERASE said the erasure complete before its CUT")
	}
	cutRefs := []string{}
	for _, cut := range refs.Cuts() {
		if cut.ErasureId == requestId {
			cutRefs = append(cutRefs, cut.Ref)
		}
	}
	if slices.Sort(cutRefs); !slices.Equal(cutRefs, []string{sidecar.DirectoryErasureTestCardsRef, sidecar.DirectoryErasureTestStreamsRef}) {
		t.Fatalf("the erasure's CUTs: %v", cutRefs)
	}
	for _, each := range []struct {
		ref      string
		document []byte
	}{
		{ref: sidecar.DirectoryErasureTestCardsRef, document: seed.repoDocument},
		{ref: sidecar.DirectoryErasureTestCardsRef, document: seed.runDocument},
		{ref: sidecar.DirectoryErasureTestStreamsRef, document: seed.repoDocument},
	} {
		if readable := refs.Readable(each.ref, each.document); len(readable) != 0 {
			t.Fatalf("on %s index versions holding %s still open: %v", each.ref, each.document, readable)
		}
	}
	if readable := refs.Readable(sidecar.DirectoryErasureTestCardsRef, []byte("a/another")); len(readable) == 0 {
		t.Fatal("the other document left the cards ref's index")
	}
	if _, _, complete := refs.Erases(requestId); complete {
		t.Fatal("the erasure reads complete while a card waits for its writer")
	}

	seed.writeRun(t, 2, true)
	pass = admin.pass(t, runner)
	files = pass.Files[requestId]
	if files == nil || !slices.Equal(files.ClosedPaths, []string{cardPath}) || !files.Complete {
		t.Fatalf("the pass after the card's writer wrote the run private: %+v", files)
	}
	if _, _, complete := refs.Erases(requestId); !complete || refs.CompleteBeforeCut(requestId) {
		t.Fatalf("the erasure's end: complete %t, complete before its CUT %t", complete, refs.CompleteBeforeCut(requestId))
	}
	for _, text := range []string{testErasureRepoTitle, testErasureProject} {
		if readable := evs.readable(t, text); len(readable) != 0 {
			t.Fatalf("stored card versions holding %q still open: %v", text, readable)
		}
	}
	refs.Sweep()
}

// A directory admin's erase of a run announced by its writer's M6 entry and held by its card at format 2: the entry's
// ERASE says nothing complete, the CUTs on both refs come next, both refs' index files are rewritten, and the card's
// removal and the ERASE of its keys end the erasure; nothing says complete before the CUT.
func TestDirectoryFormat2AdminEraseOfAnEntryAndACardSaysNothingCompleteBeforeItsCut(t *testing.T) {
	world, evs := newTestErasureWorld(t)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	runId := sidecar.NewId()
	item := testRunItem(writer.sidecarId, &memberId, runId, 1, world.clock.Now().UnixMilli())
	item.What.Title = "ship the launch plan"
	writer.announce(item)
	world.cards.RaiseFormat(world.directoryId)
	pin := world.directoryAuth.Tip().Pin()
	cardPath := sidecar.DirectoryCardPath(writer.sidecarId)
	world.putFile(writer.sidecarId, cardPath, world.cardContent(writer, writer.sidecarId, 1, pin, item), pin)
	admin := evs.adminDevice(t)
	refs := sidecar.NewDirectoryErasureTestRefs(t, admin.writer.sidecarId)
	document := testAnnouncementDocumentName(&writer.sidecarId, runId)
	refs.Enter(sidecar.DirectoryErasureTestCardsRef, writer.sidecarId, document, 1)
	refs.Enter(sidecar.DirectoryErasureTestCardsRef, writer.sidecarId, []byte("a/another"), 1)
	refs.Enter(sidecar.DirectoryErasureTestStreamsRef, writer.sidecarId, document, 1)
	evs.bindRefs(admin, refs)
	admin.mustSync(t)

	result, err := admin.client.Erase(t.Context(), &sidecar.DirectoryEraseArgs{Id: runId, Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.EntryIds) != 1 || result.Reason != sidecar.RecordErasureReasonModeration || result.Files == nil {
		t.Fatalf("the erasure: %+v", result)
	}
	if files := result.Files; files.CutCount != 2 || !slices.Equal(files.RemovedPaths, []string{cardPath}) || files.IndexPairCount == 0 || !files.Complete {
		t.Fatalf("the erasure's files: %+v", files)
	}
	if complete := world.completeStreamErasures(t, result.ErasureId); complete != 0 {
		t.Fatalf("%d of the announce entry's ERASEs said complete", complete)
	}
	if _, _, complete := refs.Erases(result.ErasureId); !complete || refs.CompleteBeforeCut(result.ErasureId) {
		t.Fatalf("the erasure's end: complete %t, complete before its CUT %t", complete, refs.CompleteBeforeCut(result.ErasureId))
	}
	for _, ref := range []string{sidecar.DirectoryErasureTestCardsRef, sidecar.DirectoryErasureTestStreamsRef} {
		if readable := refs.Readable(ref, document); len(readable) != 0 {
			t.Fatalf("on %s index versions holding the run still open: %v", ref, readable)
		}
	}
	if readable := refs.Readable(sidecar.DirectoryErasureTestCardsRef, []byte("a/another")); len(readable) == 0 {
		t.Fatal("the other document left the cards ref's index")
	}
	if readable := evs.readable(t, "ship the launch plan"); len(readable) != 0 {
		t.Fatalf("stored card versions holding the run still open: %v", readable)
	}
	refs.Sweep()
}

// The 30-day sweep's later-signed card (QD-1158's second case): after a revocation completed, the card's writer signs
// its run naming the repo again and the card's push enters its document in the cards ref's index. The next pass cuts it,
// adding it to the complete erasure, and the cards ref's rewrite lists before it trusts the complete it reads, so the
// index slot holding the document is rewritten under a fresh key while the card itself waits for its writer, its ERASE
// opening the erasure again; once the writer wrote the run private the card's CLOSURE and its ERASE end the erasure.
// Before QD-1158 the rewrite read the erasure done and left the slot holding the document under its live key, which a
// later CUT's drop of the erasure from the set would let back into search.
func TestDirectoryFormat2LaterCutOfACompleteErasureRewritesTheSlotHoldingIt(t *testing.T) {
	seed, admin, refs, erase := newTestErasureRefsSeed(t)
	evs := seed.evs
	revocation := seed.revoke(t)
	runner := testRefsRunner(t, admin, erase)
	requestId := revocation.RequestId
	cardPath := sidecar.DirectoryCardPath(seed.daemon.writer.sidecarId)
	admin.pass(t, runner)
	seed.writeRun(t, 2, true)
	if files := admin.pass(t, runner).Files[requestId]; files == nil || !files.Complete {
		t.Fatalf("the revocation's end: %+v", files)
	}
	refs.Sweep()

	seed.writeRun(t, 3, false)
	refs.Enter(sidecar.DirectoryErasureTestCardsRef, seed.daemon.writer.sidecarId, seed.runDocument, 3)
	if readable := refs.Readable(sidecar.DirectoryErasureTestCardsRef, seed.runDocument); len(readable) == 0 {
		t.Fatal("no index file holds the later card's document")
	}
	pass := admin.pass(t, runner)
	files := pass.Files[requestId]
	if files == nil || files.CutCount != 1 || files.IndexPairCount == 0 || !slices.Equal(files.WaitingPaths, []string{cardPath}) ||
		len(files.ClosedPaths) != 0 || files.Complete {
		t.Fatalf("the pass that shows the later-signed card: %+v", files)
	}
	if version := refs.ListedVersion(sidecar.DirectoryErasureTestCardsRef, requestId, seed.runDocument); version != 3 {
		t.Fatalf("the later CUT lists the run's document at %d", version)
	}
	if readable := refs.Readable(sidecar.DirectoryErasureTestCardsRef, seed.runDocument); len(readable) != 0 {
		t.Fatalf("index versions holding the later card's document still open: %v", readable)
	}
	if readable := refs.Readable(sidecar.DirectoryErasureTestCardsRef, []byte("a/another")); len(readable) == 0 {
		t.Fatal("the other document left the cards ref's index")
	}
	if _, _, complete := refs.Erases(requestId); complete {
		t.Fatal("the erasure reads complete while the later card waits for its writer")
	}
	refs.Sweep()

	seed.writeRun(t, 4, true)
	pass = admin.pass(t, runner)
	files = pass.Files[requestId]
	if files == nil || !slices.Equal(files.ClosedPaths, []string{cardPath}) || !files.Complete {
		t.Fatalf("the pass after the later card's rewrite: %+v", files)
	}
	if _, _, complete := refs.Erases(requestId); !complete {
		t.Fatal("the erasure did not end again")
	}
	if readable := evs.readable(t, testErasureProject); len(readable) != 0 {
		t.Fatalf("card versions naming the repo still open: %v", readable)
	}
	refs.Sweep()
}

// A late announce entry after a revocation completed, as an M6 client still in the fleet writes one naming the repo
// (owner decision 658; QD-1158): the next pass erases it, its ERASE saying nothing complete and so opening the
// erasure again, cuts its document on ur/index, and ur/index's rewrite, finding no file holding it, ends the erasure by
// a completion ERASE, since the binding reads the erasure's progress by its newest ERASE. Read by any ERASE that once
// said complete, the rewrite read the reopened erasure done and sent no completion, and the erasure stayed open.
func TestDirectoryFormat2LateAnnounceEntryEndsTheReopenedErasureByACompletion(t *testing.T) {
	seed, admin, refs, erase := newTestErasureRefsSeed(t)
	world := seed.world
	revocation := seed.revoke(t)
	runner := testRefsRunner(t, admin, erase)
	requestId := revocation.RequestId
	admin.pass(t, runner)
	seed.writeRun(t, 2, true)
	if files := admin.pass(t, runner).Files[requestId]; files == nil || !files.Complete {
		t.Fatalf("the revocation's end: %+v", files)
	}
	count, completions, _ := refs.Erases(requestId)

	lateMemberId := sidecar.NewId()
	late := world.memberWriter(lateMemberId)
	world.publish()
	lateRunId := sidecar.NewId()
	late.announce(testRunItemIn(world, late.sidecarId, lateMemberId, lateRunId, seed.repoId, 1, testErasureProject, false))
	pass := admin.pass(t, runner)
	files := pass.Files[requestId]
	if len(pass.Erased[requestId]) != 1 || files == nil || files.CutCount != 1 || !files.Complete {
		t.Fatalf("the pass that shows the late entry: erased %v, files %+v", pass.Erased[requestId], files)
	}
	lateDocument := testAnnouncementDocumentName(&late.sidecarId, lateRunId)
	if version := refs.ListedVersion(sidecar.DirectoryErasureTestStreamsRef, requestId, lateDocument); version != 1 {
		t.Fatalf("ur/index lists the late entry's document at %d", version)
	}
	after, afterCompletions, complete := refs.Erases(requestId)
	if !complete || after != count+2 || afterCompletions != completions+1 {
		t.Fatalf("after the late entry: %d ERASEs more, %d completions more, complete %t", after-count, afterCompletions-completions, complete)
	}
	if live := admin.liveAnnouncements(t); len(live) != 0 {
		t.Fatalf("announce entries naming the repo with a key left: %v", live)
	}
	refs.Sweep()
}
