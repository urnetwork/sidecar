//go:build !sidecar_http && !ios_extension

// A request past its 30-day sweep window (QD-1161, QD-1166; §16.11's runner, closure and erasure rows, §11.12's
// reconcile row, §11.13's wait row; FI-19): the directory's erasure runner still finishes what the request's ledger row
// owes of format 2's half, and catches nothing new. The sweep's later-signed card cut near the window's end, the cards
// ref's rewrite then waiting on the eraser's allowance, has the slot holding its document rewritten under a fresh key
// past the window, nothing said complete while the card waits for its writer, and another member's card first found
// then is left uncut; once the card's writer wrote the run private past the window the card, met inside it, is
// rewritten by CLOSURE and its ERASE ends the erasure, which the next CUT on each ref drops from the set, while the
// other member's card, first met past the window, is not touched though its writer wrote it private too; a second drop
// near the window's end, which puts the document back uncut, and a CUT a full set refused there each have it cut and
// the slot rewritten past the window; a later-signed card first found past the window is not cut; and a kill between a
// card's CLOSURE and its ERASE near the window's end has the ERASE of the orphan's keys sent past it, ending the
// erasure. Inside the window, a kill between an announce entry's ERASE and the CUT of the document it folded into on
// ur/index, which the next sync no longer finds, still has that document cut by the device started again: it was
// journaled owed a CUT before the ERASE. FI-19's index and keys clauses on both refs after each step. The fakes are
// QD-1160's (directory_erasure_dropped_test.go): both index refs are the index's own erasers on its in-memory fake with
// one erasure ref between them.

package sidecar_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// The next CUT each index ref of a device refuses, by ref name, as a full set or a kill would; and the refs whose next
// rewrite reads its erasure complete with nothing left to rewrite there, as the eraser answers then, sending nothing,
// with how many rewrites answered so.
type testWindowHooks struct {
	refuseCut     map[string]error
	readDone      map[string]bool
	readDoneCount int
}

// One index ref's eraser of one call, hooked.
type testWindowIndex struct {
	sidecar.DirectoryErasureIndex
	ref   string
	hooks *testWindowHooks
}

func (self *testWindowIndex) Cut(ctx context.Context, args *sidecar.IndexCutArgs) (*sidecar.IndexCutResult, error) {
	if err, ok := self.hooks.refuseCut[self.ref]; ok {
		delete(self.hooks.refuseCut, self.ref)
		return nil, err
	}
	return self.DirectoryErasureIndex.Cut(ctx, args)
}

func (self *testWindowIndex) Rewrite(ctx context.Context, args *sidecar.IndexRewriteArgs) (*sidecar.IndexRewriteResult, error) {
	if self.hooks.readDone[self.ref] {
		delete(self.hooks.readDone, self.ref)
		self.hooks.readDoneCount += 1
		return &sidecar.IndexRewriteResult{Erasure: &sidecar.SidecarErasure{ErasureId: args.ErasureId, State: sidecar.SidecarErasureDone}, Attempts: 1}, nil
	}
	return self.DirectoryErasureIndex.Rewrite(ctx, args)
}

// A device's reach with both index refs' erasers hooked.
type testWindowFiles struct {
	sidecar.DirectoryErasureFiles
	hooks *testWindowHooks
}

func (self *testWindowFiles) CardsIndex(ctx context.Context, repoId sidecar.Id) (sidecar.DirectoryErasureIndex, error) {
	index, err := self.DirectoryErasureFiles.CardsIndex(ctx, repoId)
	if err != nil {
		return nil, err
	}
	return &testWindowIndex{DirectoryErasureIndex: index, ref: sidecar.DirectoryErasureTestCardsRef, hooks: self.hooks}, nil
}

func (self *testWindowFiles) StreamsIndex(ctx context.Context, repoId sidecar.Id) (sidecar.DirectoryErasureIndex, error) {
	index, err := self.DirectoryErasureFiles.StreamsIndex(ctx, repoId)
	if err != nil {
		return nil, err
	}
	return &testWindowIndex{DirectoryErasureIndex: index, ref: sidecar.DirectoryErasureTestStreamsRef, hooks: self.hooks}, nil
}

// Binds device's format-2 erasers to files with both index refs hooked.
func testBindWindow(device *testDirectoryDevice, files sidecar.DirectoryErasureFiles) *testWindowHooks {
	hooks := &testWindowHooks{refuseCut: map[string]error{}, readDone: map[string]bool{}}
	device.client.BindErasureFiles(&testWindowFiles{DirectoryErasureFiles: files, hooks: hooks})
	return hooks
}

// Advances the world's clock until device's copy holds the request's entry pushed at least age ago, and publishes the
// state there.
func testAgeRequest(t *testing.T, world *testDirectoryWorld, device *testDirectoryDevice, requestId sidecar.Id, age time.Duration) {
	t.Helper()
	for _, request := range device.client.ErasureRequests() {
		if request.RequestId != requestId {
			continue
		}
		at := time.UnixMilli(request.PushTimeMillis).Add(age)
		if now := world.clock.Now(); now.Before(at) {
			world.clock.Advance(at.Sub(now))
		}
		world.publish()
		return
	}
	t.Fatalf("the copy holds no request %s", requestId)
}

// The sweep window's default, inside which every copy a sync shows is caught.
func testSweepWindow() time.Duration {
	return sidecar.DefaultDirectoryErasureSettings().SweepWindow
}

// The project another member's run names the repo under, told apart from the daemon's in the cards' stored versions.
const testWindowOtherProject = "example.org/team/vault-audit"

// Another member's daemon whose card's run names the repo.
type testWindowMember struct {
	world    *testDirectoryWorld
	repoId   sidecar.Id
	device   *testDirectoryDevice
	memberId sidecar.Id
	runId    sidecar.Id
	cardPath string
	// the run's document's name
	document []byte
}

// Another member's daemon signs a card whose run names the repo under testWindowOtherProject, its document entered in
// the cards ref's index as the card's push enters it: a copy no sync of the admin's has shown yet.
func (self *testErasureSeed) otherMemberCard(t *testing.T, refs *sidecar.DirectoryErasureTestRefs) *testWindowMember {
	t.Helper()
	world := self.world
	memberId := sidecar.NewId()
	device := world.device(world.memberWriter(memberId))
	world.publish()
	writerId := device.writer.sidecarId
	member := &testWindowMember{
		world: world, repoId: self.repoId, device: device, memberId: memberId, runId: sidecar.NewId(),
		cardPath: sidecar.DirectoryCardPath(writerId),
	}
	member.document = testAnnouncementDocumentName(&writerId, member.runId)
	member.writeRun(t, 1, false)
	refs.Enter(sidecar.DirectoryErasureTestCardsRef, writerId, member.document, 1)
	return member
}

// The member's card again with its run at version, private or naming the repo.
func (self *testWindowMember) writeRun(t *testing.T, version uint64, private bool) {
	t.Helper()
	self.world.clock.Advance(time.Minute)
	self.world.publish()
	writerId := self.device.writer.sidecarId
	self.device.writeCard(t, testRunItemIn(self.world, writerId, self.memberId, self.runId, self.repoId, version, testWindowOtherProject, private))
}

// The stored versions of the card at path holding text whose key still stands.
func testReadableAt(t *testing.T, evs *testErasureEvs, text string, path string) []string {
	t.Helper()
	return slices.DeleteFunc(evs.readable(t, text), func(version string) bool { return !strings.HasPrefix(version, path+"@") })
}

// The sweep's CUT of the later-signed card an hour before the window's end, the cards ref's rewrite then waiting on the
// eraser's allowance before any pair: the set lists the card's document and its slot keeps it under its live key, the
// erasure still reading complete by its newest ERASE, as another erasure's CUT would drop it. Past the window the
// rewrite the ledger owes runs, the slot is rewritten under a fresh key and the pair's ERASE opens the erasure while
// the card waits for its writer, so another erasure's CUT keeps it in the set; another member's card that names the
// repo, first found past the window, is not cut. The card's writer then writes the run private, and the other
// member's writer too: the card, met inside the window, is rewritten by CLOSURE past it and its ERASE ends the
// erasure (QD-1166), which the next CUT on each ref drops from the set; the other member's card, first met past the
// window, is not touched. Before QD-1161 the pass past the window skipped the request, so the slot kept the document
// under its live key, and a later CUT's drop of the erasure let it back into search; before QD-1166 the card stayed
// owed its CLOSURE past the window, its earlier versions keeping their key, and the erasure stayed open and listed.
func TestDirectoryFormat2RewriteWaitingOnTheAllowanceFinishesPastTheWindow(t *testing.T) {
	seed := newTestDroppedSeed(t)
	refs := seed.refs
	cardsRef := sidecar.DirectoryErasureTestCardsRef
	testAgeRequest(t, seed.world, seed.admin, seed.requestId, testSweepWindow()-time.Hour)
	refs.RefuseNextClosure(cardsRef)
	files := seed.admin.pass(t, seed.runner).Files[seed.requestId]
	if files == nil || files.CutCount != 1 || files.IndexPairCount != 0 || !files.IndexWaiting || files.Complete ||
		!slices.Equal(files.WaitingPaths, []string{seed.cardPath}) {
		t.Fatalf("the pass an hour before the window's end: %+v", files)
	}
	if version := refs.ListedVersion(cardsRef, seed.requestId, seed.runDocument); version != 3 {
		t.Fatalf("the sweep's CUT lists the later card's document at %d", version)
	}
	if readable := refs.Readable(cardsRef, seed.runDocument); len(readable) == 0 {
		t.Fatal("a rewrite took the later card's document while it waited on the allowance")
	}
	if _, _, complete := refs.Erases(seed.requestId); !complete {
		t.Fatal("the erasure reads open before any pair of the waiting rewrite")
	}

	testAgeRequest(t, seed.world, seed.admin, seed.requestId, testSweepWindow()+time.Hour)
	other := seed.otherMemberCard(t, refs)
	pass := seed.admin.pass(t, seed.runner)
	files = pass.Files[seed.requestId]
	if len(pass.Erased[seed.requestId]) != 0 || files == nil || files.CutCount != 0 || files.IndexPairCount == 0 || files.IndexWaiting ||
		files.Complete || !slices.Equal(files.WaitingPaths, []string{seed.cardPath}) || len(files.ClosedPaths) != 0 {
		t.Fatalf("the pass past the window: erased %v, files %+v", pass.Erased[seed.requestId], files)
	}
	if version := refs.ListedVersion(cardsRef, seed.requestId, other.document); version != 0 {
		t.Fatalf("a card first found past the window is cut at %d", version)
	}
	if readable := refs.Readable(cardsRef, other.document); len(readable) == 0 {
		t.Fatal("the rewrite past the window took a document no CUT lists")
	}
	seed.slotRewritten(t)
	seed.otherCut(t, refs.Open(cardsRef, seed.otherId), "past the window")
	if !refs.Lists(cardsRef, seed.requestId) {
		t.Fatal("another erasure's CUT dropped the erasure the rewrite opened")
	}
	// the card still names the repo: the ledger shows it owed its CLOSURE, so the pass reads it, and sends nothing
	pass = seed.admin.pass(t, seed.runner)
	if files := pass.Files[seed.requestId]; files != nil || !slices.Equal(pass.Waiting, []sidecar.Id{seed.requestId}) {
		t.Fatalf("a pass past the window with the card waiting for its writer: waiting %v, files %+v", pass.Waiting, files)
	}

	closures := len(seed.evs.cardClosures())
	seed.writeRun(t, 4, true)
	other.writeRun(t, 2, true)
	pass = seed.admin.pass(t, seed.runner)
	files = pass.Files[seed.requestId]
	if len(pass.Erased[seed.requestId]) != 0 || files == nil || !slices.Equal(files.ClosedPaths, []string{seed.cardPath}) || !files.Complete ||
		files.CutCount != 0 || files.IndexPairCount != 0 || len(files.WaitingPaths) != 0 {
		t.Fatalf("the pass after both writers wrote their runs private past the window: erased %v, files %+v", pass.Erased[seed.requestId], files)
	}
	if after := seed.evs.cardClosures(); len(after) != closures+1 || after[len(after)-1].path != seed.cardPath || after[len(after)-1].erasureId != seed.requestId {
		t.Fatalf("the cards ref's CLOSUREs past the window: %d more", len(after)-closures)
	}
	if readable := seed.evs.readable(t, testErasureProject); len(readable) != 0 {
		t.Fatalf("versions of the card met inside the window still open: %v", readable)
	}
	if readable := testReadableAt(t, seed.evs, testWindowOtherProject, other.cardPath); len(readable) == 0 {
		t.Fatal("the card first met past the window lost its key")
	}
	if _, _, complete := refs.Erases(seed.requestId); !complete {
		t.Fatal("the erasure reads open after the CLOSURE's ERASE")
	}
	refs.Sweep()
	// the next CUT on each ref, another erasure's, drops the complete erasure from its set
	for _, ref := range []string{cardsRef, sidecar.DirectoryErasureTestStreamsRef} {
		seed.otherCut(t, refs.Open(ref, seed.otherId), "after the end on "+ref)
		if refs.Lists(ref, seed.requestId) {
			t.Fatalf("%s's set lists the erasure after it ended", ref)
		}
	}
	refs.Sweep()
	if files := seed.admin.pass(t, seed.runner).Files[seed.requestId]; files != nil {
		t.Fatalf("a pass past the window after the erasure ended: %+v", files)
	}
	if after := len(seed.evs.cardClosures()); after != closures+1 {
		t.Fatalf("%d CLOSUREs of the cards ref after the erasure ended", after-closures-1)
	}
}

// The cards ref's rewrite waits on the allowance an hour before the window's end, as above, and the card's writer
// writes the run private past the window. The pass runs the rewrite the ledger owes, then rewrites the card, met inside
// the window, by CLOSURE, and that CLOSURE's ERASE of its keys ends the erasure (QD-1166): the next CUT on the cards
// ref drops it from the set. Before QD-1166 the card stayed owed its CLOSURE past the window, its earlier versions
// keeping their key, and the erasure stayed open and listed for good, holding set room.
func TestDirectoryFormat2CardMetInsideTheWindowIsRewrittenPastIt(t *testing.T) {
	seed := newTestDroppedSeed(t)
	refs := seed.refs
	cardsRef := sidecar.DirectoryErasureTestCardsRef
	testAgeRequest(t, seed.world, seed.admin, seed.requestId, testSweepWindow()-time.Hour)
	refs.RefuseNextClosure(cardsRef)
	if files := seed.admin.pass(t, seed.runner).Files[seed.requestId]; files == nil || !files.IndexWaiting || files.IndexPairCount != 0 {
		t.Fatalf("the pass an hour before the window's end: %+v", files)
	}
	closures := len(seed.evs.cardClosures())

	testAgeRequest(t, seed.world, seed.admin, seed.requestId, testSweepWindow()+time.Hour)
	seed.writeRun(t, 4, true)
	pass := seed.admin.pass(t, seed.runner)
	files := pass.Files[seed.requestId]
	if len(pass.Erased[seed.requestId]) != 0 || files == nil || files.CutCount != 0 || files.IndexPairCount == 0 || files.IndexWaiting ||
		!files.Complete || !slices.Equal(files.ClosedPaths, []string{seed.cardPath}) || len(files.WaitingPaths) != 0 {
		t.Fatalf("the pass past the window: erased %v, files %+v", pass.Erased[seed.requestId], files)
	}
	if after := len(seed.evs.cardClosures()); after != closures+1 {
		t.Fatalf("%d CLOSUREs of the cards ref past the window", after-closures)
	}
	if readable := seed.evs.readable(t, testErasureProject); len(readable) != 0 {
		t.Fatalf("versions of the card met inside the window still open: %v", readable)
	}
	if version := refs.ListedVersion(cardsRef, seed.requestId, seed.runDocument); version != 3 {
		t.Fatalf("the cards ref's set lists the later card's document at %d", version)
	}
	if readable := refs.Readable(cardsRef, seed.runDocument); len(readable) != 0 {
		t.Fatalf("index versions holding the later card's document still open: %v", readable)
	}
	if readable := refs.Readable(cardsRef, []byte("a/another")); len(readable) == 0 {
		t.Fatal("the other document left the cards ref's index")
	}
	if _, _, complete := refs.Erases(seed.requestId); !complete {
		t.Fatal("the erasure reads open after the CLOSURE's ERASE")
	}
	refs.Sweep()
	seed.otherCut(t, refs.Open(cardsRef, seed.otherId), "after the end")
	if refs.Lists(cardsRef, seed.requestId) {
		t.Fatal("the cards ref's set lists the erasure after it ended")
	}
	refs.Sweep()
	if files := seed.admin.pass(t, seed.runner).Files[seed.requestId]; files != nil {
		t.Fatalf("a pass past the window after the erasure ended: %+v", files)
	}
}

// Another directory admin's CUT drops the erasure an hour before the window's end after the sweep's CUT of the
// later-signed card and again after its CUT again, so the document goes back uncut in the ledger, owed a CUT there.
// Past the window the pass CUTs it, as the ledger owes, though it CUTs nothing the sync finds then, and rewrites the
// slot under a fresh key. Before QD-1161 nothing ran past the window and the slot kept the document unlisted under its
// live key, back in search.
func TestDirectoryFormat2SecondDropNearTheWindowsEndIsCutPastIt(t *testing.T) {
	seed := newTestDroppedSeed(t)
	refs := seed.refs
	cardsRef := sidecar.DirectoryErasureTestCardsRef
	testAgeRequest(t, seed.world, seed.admin, seed.requestId, testSweepWindow()-time.Hour)
	drops := 0
	seed.hooks.afterCut = func(args *sidecar.IndexCutArgs) {
		if args.ErasureId != seed.requestId || 2 <= drops {
			return
		}
		drops += 1
		seed.otherCut(t, refs.Open(cardsRef, seed.otherId), fmt.Sprintf("drop %d", drops))
	}
	files := seed.admin.pass(t, seed.runner).Files[seed.requestId]
	if drops != 2 || files == nil || files.CutCount != 2 || files.IndexPairCount != 0 || !files.IndexWaiting || files.Complete {
		t.Fatalf("the pass dropped twice an hour before the window's end: %d drops, files %+v", drops, files)
	}
	if refs.Lists(cardsRef, seed.requestId) {
		t.Fatal("the set lists the erasure after its second drop")
	}
	if readable := refs.Readable(cardsRef, seed.runDocument); len(readable) == 0 {
		t.Fatal("a rewrite took the later card's document while its erasure was off the set")
	}
	refs.Sweep()

	testAgeRequest(t, seed.world, seed.admin, seed.requestId, testSweepWindow()+time.Hour)
	pass := seed.admin.pass(t, seed.runner)
	files = pass.Files[seed.requestId]
	if len(pass.Erased[seed.requestId]) != 0 || files == nil || files.CutCount != 1 || files.IndexPairCount == 0 || files.IndexWaiting ||
		files.Complete || !slices.Equal(files.WaitingPaths, []string{seed.cardPath}) {
		t.Fatalf("the pass past the window: erased %v, files %+v", pass.Erased[seed.requestId], files)
	}
	seed.slotRewritten(t)
	if files := seed.admin.pass(t, seed.runner).Files[seed.requestId]; files != nil {
		t.Fatalf("a pass past the window with nothing owed: %+v", files)
	}
}

// The sweep's CUT of the later-signed card meets a full erasure set an hour before the window's end, so nothing of the
// card's document is listed and the call waits, the document journaled owed a CUT. Past the window, with room in the
// set, the pass CUTs it and rewrites the slot, as the ledger owes: it was found inside the window. Before QD-1161 the
// ledger held no document a full set refused, and nothing past the window would have cut it.
func TestDirectoryFormat2CutAFullSetRefusedNearTheWindowsEndIsSentPastIt(t *testing.T) {
	seed := newTestDroppedSeed(t)
	refs := seed.refs
	cardsRef := sidecar.DirectoryErasureTestCardsRef
	hooks := testBindWindow(seed.admin, &testDroppedClient{
		testErasureRefsClient: &testErasureRefsClient{
			testErasureClient: &testErasureClient{evs: seed.evs, sidecarId: seed.admin.writer.sidecarId}, refs: refs,
		},
		hooks: seed.hooks,
	})
	testAgeRequest(t, seed.world, seed.admin, seed.requestId, testSweepWindow()-time.Hour)
	hooks.refuseCut[cardsRef] = sidecar.ErrIndexErasureSetFull
	files := seed.admin.pass(t, seed.runner).Files[seed.requestId]
	if files == nil || files.CutCount != 0 || files.IndexPairCount != 0 || !files.IndexWaiting || files.Complete {
		t.Fatalf("the pass whose CUT the full set refused: %+v", files)
	}
	if version := refs.ListedVersion(cardsRef, seed.requestId, seed.runDocument); version != 1 {
		t.Fatalf("the set lists the run's document at %d, not the revocation's version", version)
	}
	refs.Sweep()

	testAgeRequest(t, seed.world, seed.admin, seed.requestId, testSweepWindow()+time.Hour)
	files = seed.admin.pass(t, seed.runner).Files[seed.requestId]
	if files == nil || files.CutCount != 1 || files.IndexPairCount == 0 || files.IndexWaiting || files.Complete ||
		!slices.Equal(files.WaitingPaths, []string{seed.cardPath}) {
		t.Fatalf("the pass past the window: %+v", files)
	}
	seed.slotRewritten(t)
}

// After a revocation completed, the card's writer signs its run naming the repo again past the window, and the card's
// push enters its document in the cards ref's index. The ledger owes the request nothing, so the pass sends nothing for
// it: no CUT lists the later version, the erasure stays complete, and the document stands in its slot, a copy the
// request no longer catches (§16.11's revoke row: for 30 days).
func TestDirectoryFormat2LaterSignedCardFirstFoundPastTheWindowIsNotCut(t *testing.T) {
	seed, admin, refs, erase := newTestErasureRefsSeed(t)
	cardsRef := sidecar.DirectoryErasureTestCardsRef
	revocation := seed.revoke(t)
	runner := testRefsRunner(t, admin, erase)
	requestId := revocation.RequestId
	admin.pass(t, runner)
	seed.writeRun(t, 2, true)
	if files := admin.pass(t, runner).Files[requestId]; files == nil || !files.Complete {
		t.Fatalf("the revocation's end: %+v", files)
	}
	refs.Sweep()
	count, _, _ := refs.Erases(requestId)
	cutCount := len(refs.Cuts())

	testAgeRequest(t, seed.world, admin, requestId, testSweepWindow()+time.Hour)
	seed.writeRun(t, 3, false)
	refs.Enter(cardsRef, seed.daemon.writer.sidecarId, seed.runDocument, 3)
	pass := admin.pass(t, runner)
	if len(pass.Erased) != 0 || pass.Files[requestId] != nil || len(pass.Waiting) != 0 || len(pass.Delayed) != 0 || len(pass.Pending) != 0 {
		t.Fatalf("the pass that first shows the later card past the window: %+v", pass)
	}
	if version := refs.ListedVersion(cardsRef, requestId, seed.runDocument); version != 1 {
		t.Fatalf("the set lists the run's document at %d", version)
	}
	if after, _, complete := refs.Erases(requestId); after != count || !complete || len(refs.Cuts()) != cutCount {
		t.Fatalf("past the window: %d ERASEs more, complete %t, %d CUTs more", after-count, complete, len(refs.Cuts())-cutCount)
	}
	if readable := refs.Readable(cardsRef, seed.runDocument); len(readable) == 0 {
		t.Fatal("no index file holds the later card's document")
	}
	refs.Sweep()
}

// The card's writer writes its run private an hour before the window's end and the pass dies between the card's CLOSURE
// and that CLOSURE's ERASE, so the card's earlier versions, naming the repo, keep their key. Past the window the pass
// sends the ERASE the ledger owes, of the orphaned CLOSURE's keys by evs's state, and with nothing else owed that ERASE
// ends the erasure. Before QD-1161 the pass past the window skipped the request, and the keys stood.
func TestDirectoryFormat2OrphanedClosureNearTheWindowsEndIsErasedPastIt(t *testing.T) {
	seed, admin, refs, erase := newTestErasureRefsSeed(t)
	evs := seed.evs
	revocation := seed.revoke(t)
	runner := testRefsRunner(t, admin, erase)
	requestId := revocation.RequestId
	cardPath := sidecar.DirectoryCardPath(seed.daemon.writer.sidecarId)
	if files := admin.pass(t, runner).Files[requestId]; files == nil || !slices.Equal(files.WaitingPaths, []string{cardPath}) {
		t.Fatalf("the first pass: %+v", files)
	}
	testAgeRequest(t, seed.world, admin, requestId, testSweepWindow()-time.Hour)
	seed.writeRun(t, 2, true)
	evs.failEraseCount = 1
	admin.mustSync(t)
	if _, err := runner.Pass(t.Context()); err == nil {
		t.Fatal("the pass killed after the card's CLOSURE returned no error")
	}
	if closures := evs.cardClosures(); len(closures) != 2 || closures[1].path != cardPath {
		t.Fatalf("the cards ref's CLOSUREs after the kill: %d", len(closures))
	}
	if readable := evs.readable(t, testErasureProject); len(readable) == 0 {
		t.Fatal("the CLOSURE's old key went without its ERASE")
	}
	count, _, _ := refs.Erases(requestId)

	testAgeRequest(t, seed.world, admin, requestId, testSweepWindow()+time.Hour)
	pass := admin.pass(t, runner)
	files := pass.Files[requestId]
	if len(pass.Erased[requestId]) != 0 || files == nil || files.ErasedKeyCount == 0 || !files.Complete || files.CutCount != 0 ||
		len(files.ClosedPaths) != 0 {
		t.Fatalf("the pass past the window: erased %v, files %+v", pass.Erased[requestId], files)
	}
	if readable := evs.readable(t, testErasureProject); len(readable) != 0 {
		t.Fatalf("card versions naming the repo still open: %v", readable)
	}
	if after, _, complete := refs.Erases(requestId); after != count+1 || !complete {
		t.Fatalf("past the window: %d ERASEs more, complete %t", after-count, complete)
	}
	refs.Sweep()
	if files := admin.pass(t, runner).Files[requestId]; files != nil {
		t.Fatalf("a pass past the window with nothing owed: %+v", files)
	}
}

// A kill inside the window between the announce entry's ERASE, which committed, and the CUT on ur/index of the
// document the entry folded into: the device, started again, finds no live entry, so no sync shows the document again,
// and it CUTs it on ur/index all the same, journaled owed a CUT in the copy before the ERASE, and rewrites the index
// file holding it. Before the journal the document stayed in that file unlisted under its live key, in search for good.
func TestDirectoryFormat2KillBetweenAnEntrysEraseAndItsCutStillCutsItsDocument(t *testing.T) {
	seed, admin, refs, erase := newTestErasureRefsSeed(t)
	streamsRef := sidecar.DirectoryErasureTestStreamsRef
	hooks := testBindWindow(admin, &testErasureRefsClient{
		testErasureClient: &testErasureClient{evs: seed.evs, sidecarId: admin.writer.sidecarId}, refs: refs,
	})
	revocation := seed.revoke(t)
	runner := testRefsRunner(t, admin, erase)
	requestId := revocation.RequestId
	crash := errors.New("the device stopped")
	hooks.refuseCut[streamsRef] = crash
	admin.mustSync(t)
	pass, err := runner.Pass(t.Context())
	if !errors.Is(err, crash) || len(pass.Erased[requestId]) != 1 {
		t.Fatalf("the pass killed before its CUT on ur/index: %v, erased %v", err, pass.Erased[requestId])
	}
	if live := admin.liveAnnouncements(t); len(live) != 0 {
		t.Fatalf("announce entries naming the repo with a key left: %v", live)
	}
	if refs.Lists(streamsRef, requestId) {
		t.Fatal("ur/index lists the erasure before its CUT")
	}
	if readable := refs.Readable(streamsRef, seed.repoDocument); len(readable) == 0 {
		t.Fatal("no index file of ur/index holds the entry's document")
	}

	restarted := seed.world.restarted(admin)
	restartedRunner := testRefsRunner(t, restarted, seed.evs.bindRefs(restarted, refs))
	pass = restarted.pass(t, restartedRunner)
	files := pass.Files[requestId]
	if len(pass.Erased[requestId]) != 0 || files == nil || files.CutCount != 1 || files.IndexPairCount == 0 || files.Complete {
		t.Fatalf("the pass after the kill: erased %v, files %+v", pass.Erased[requestId], files)
	}
	if version := refs.ListedVersion(streamsRef, requestId, seed.repoDocument); version != 1 {
		t.Fatalf("ur/index lists the entry's document at %d", version)
	}
	for _, each := range []struct {
		ref      string
		document []byte
	}{
		{ref: streamsRef, document: seed.repoDocument},
		{ref: sidecar.DirectoryErasureTestCardsRef, document: seed.repoDocument},
		{ref: sidecar.DirectoryErasureTestCardsRef, document: seed.runDocument},
	} {
		if readable := refs.Readable(each.ref, each.document); len(readable) != 0 {
			t.Fatalf("on %s index versions holding %s still open: %v", each.ref, each.document, readable)
		}
	}
	refs.Sweep()
}
