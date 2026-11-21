//go:build !sidecar_http && !ios_extension

// A revocation request an ERASE names whose check then fails (QD-1167; §16.11's revoke, runner and erasure rows,
// §11.12's reconcile row, §11.13's wait row; FI-19): its repo announced again, so it lapsed for good (owner decision
// 472); its signer's signature voided by a compromise revocation from before the request (§7.10); or another admin of
// the repo revoking it again, the later marker standing over the request's own (QD-1061). The directory's erasure
// runner still finishes what the request's ledger row owes of format 2's half, in QD-1161's form whatever the window:
// a cards ref rewrite that waited on the eraser's allowance, the ERASE after a CLOSURE a kill cut off, and the CUTs a
// full set held back. It catches nothing new for the request: another member's card naming the repo, first found after
// the check failed, is not cut under it, though a superseding request cuts it under its own id, and no card or repo
// file is rewritten for it, a card it met whose writer then wrote the run private staying owed its CLOSURE and keeping
// every ERASE of the call from saying complete. No such request alarms bad_erasure. Before QD-1167 the pass skipped
// such a request before it read the ledger, so the slots holding its documents kept them under live keys and an
// orphaned CLOSURE's keys stood. FI-19's index and keys clauses on both refs after each step. The fakes are QD-1160's
// and QD-1161's (directory_erasure_dropped_test.go, directory_erasure_window_test.go): both index refs are the index's
// own erasers on its in-memory fake with one erasure ref between them.

package sidecar_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// How a request's check comes to fail once an ERASE names it.
type testBegunCheck int

const (
	// its repo's owner announces the repo again: the request lapsed for good
	testBegunLapsed testBegunCheck = iota + 1
	// a compromise revocation of its signer, from the request's own push on, voids its signature
	testBegunVoided
	// another admin of the repo revokes it again, and the later marker stands over the request's own
	testBegunSuperseded
)

func (self testBegunCheck) String() string {
	switch self {
	case testBegunLapsed:
		return "lapsed"
	case testBegunVoided:
		return "voided"
	case testBegunSuperseded:
		return "superseded"
	}
	return fmt.Sprintf("check %d", int(self))
}

// Every way the check fails.
func testBegunChecks() []testBegunCheck {
	return []testBegunCheck{testBegunLapsed, testBegunVoided, testBegunSuperseded}
}

// A revocation's request whose erasure a directory admin's runner works on both index refs, its CUTs hooked.
type testBegunSeed struct {
	*testErasureSeed
	admin     *testDirectoryDevice
	refs      *sidecar.DirectoryErasureTestRefs
	runner    *sidecar.DirectoryErasureRunner
	hooks     *testWindowHooks
	requestId sidecar.Id
	cardPath  string
	repoPath  string
	// the request that superseded it, once one did
	laterId sidecar.Id
}

func newTestBegunSeed(t *testing.T) *testBegunSeed {
	t.Helper()
	seed, admin, refs, erase := newTestErasureRefsSeed(t)
	hooks := testBindWindow(admin, &testErasureRefsClient{
		testErasureClient: &testErasureClient{evs: seed.evs, sidecarId: admin.writer.sidecarId}, refs: refs,
	})
	revocation := seed.revoke(t)
	return &testBegunSeed{
		testErasureSeed: seed, admin: admin, refs: refs, runner: testRefsRunner(t, admin, erase), hooks: hooks,
		requestId: revocation.RequestId, cardPath: sidecar.DirectoryCardPath(seed.daemon.writer.sidecarId),
		repoPath: sidecar.DirectoryRepoPath(seed.repoId),
	}
}

// The request as the admin's copy holds it.
func (self *testBegunSeed) request(t *testing.T) *sidecar.DirectoryErasureRequestView {
	t.Helper()
	for _, request := range self.admin.client.ErasureRequests() {
		if request.RequestId == self.requestId {
			return request
		}
	}
	t.Fatalf("the admin's copy holds no request %s", self.requestId)
	return nil
}

// Makes the request's check fail as check says, an ERASE naming it already.
func (self *testBegunSeed) failCheck(t *testing.T, check testBegunCheck) {
	t.Helper()
	world := self.world
	// the copy reads its own ERASEs at its next sync
	self.admin.mustSync(t)
	if request := self.request(t); !request.Erased {
		t.Fatalf("%s: no ERASE names the request before its check fails", check)
	}
	switch check {
	case testBegunLapsed:
		self.owner.mustSync(t)
		if _, err := self.owner.client.AnnounceRepo(t.Context(), &sidecar.DirectoryRepoAnnounceArgs{RepoId: self.repoId, DisplayName: testErasureRepoTitle, Confirmed: true}); err != nil {
			t.Fatal(err)
		}
		self.owner.flush(t)
	case testBegunVoided:
		since := self.request(t).PushPin.GetVersion()
		ownerId := self.owner.writer.sidecarId
		admission := world.directoryFixture.Sidecars[ownerId]
		admission.RevokedAt = world.directoryAuth.Tip().Pin().GetVersion() + 1
		admission.CompromisedSince = since
		world.recordFixture.CompromisedSince = map[sidecar.Id]uint64{ownerId: since}
		world.publish()
	case testBegunSuperseded:
		writer := world.memberWriter(sidecar.NewId())
		repo := world.directoryFixture.Repos[self.repoId]
		repo.Admins = append(repo.Admins, sidecartest.FakeDirectoryRepoAdmin{SidecarId: writer.sidecarId, At: world.directoryAuth.Tip().Pin().GetVersion() + 1})
		world.publish()
		later := world.device(writer)
		later.mustSync(t)
		revocation, err := later.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: self.repoId, Confirmed: true})
		if err != nil {
			t.Fatal(err)
		}
		if revocation.RequestId == self.requestId || revocation.MarkerVersion <= self.request(t).MarkerVersion {
			t.Fatalf("the later revocation: %+v", revocation)
		}
		later.flush(t)
		self.laterId = revocation.RequestId
	}
}

// What a pass after the check failed must show of it: the check read as check says, the request neither refused nor
// alarmed, and nothing the request's announce entries held erased again.
func (self *testBegunSeed) checkFailed(t *testing.T, check testBegunCheck, pass *sidecar.DirectoryErasurePass) {
	t.Helper()
	request := self.request(t)
	switch check {
	case testBegunLapsed:
		if request.LapsedVersion <= request.MarkerVersion {
			t.Fatalf("%s: the request lapsed at %d", check, request.LapsedVersion)
		}
	case testBegunVoided:
		if !self.world.directoryAuth.Tip().SignatureVoided(request.SignerSidecarId, request.PushPin.GetVersion()) {
			t.Fatalf("%s: the request's signature stands", check)
		}
	case testBegunSuperseded:
		if !slices.Contains(pass.Superseded, self.requestId) {
			t.Fatalf("%s: the pass read superseded %v", check, pass.Superseded)
		}
	}
	if slices.Contains(pass.Refused, self.requestId) || len(pass.Erased[self.requestId]) != 0 ||
		slices.ContainsFunc(pass.Pending, func(pending *sidecar.DirectoryErasurePending) bool {
			return pending.Request.RequestId == self.requestId
		}) {
		t.Fatalf("%s: the pass refused %v, erased %v, pending %d", check, pass.Refused, pass.Erased[self.requestId], len(pass.Pending))
	}
	if count := self.admin.alarmsNaming(sidecar.SidecarRecordAlarmBadErasure, self.owner.writer.sidecarId); count != 0 {
		t.Fatalf("%s: %d bad_erasure alarms naming the request's signer", check, count)
	}
}

// Another directory admin's CUT on the ref named ref, of an erasure of its own listing a document no index file holds:
// as every CUT does, it drops from the set each erasure it reads complete.
func (self *testBegunSeed) otherAdminCut(t *testing.T, ref string) {
	t.Helper()
	otherId := sidecar.NewId()
	self.refs.Admit(otherId)
	index := self.refs.Open(ref, otherId)
	key, err := index.DocKey([]byte("a/elsewhere"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := index.Cut(t.Context(), &sidecar.IndexCutArgs{ErasureId: sidecar.NewId(), Documents: []*sidecar.IndexCutDocument{{Key: key, Version: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Pushed {
		t.Fatalf("the other erasure's CUT pushed nothing: %+v", result)
	}
}

// The cards ref's CLOSUREs of the request's erasure.
func (self *testBegunSeed) requestClosures() []*testErasurePush {
	return slices.DeleteFunc(self.evs.cardClosures(), func(closure *testErasurePush) bool { return closure.erasureId != self.requestId })
}

// Another member's card naming the repo, first found after the check failed, is no copy of the request's: no CUT of
// its lists it, while a superseding request's does, inside its own window.
func (self *testBegunSeed) noNewCopy(t *testing.T, check testBegunCheck, other *testWindowMember) {
	t.Helper()
	cardsRef := sidecar.DirectoryErasureTestCardsRef
	if version := self.refs.ListedVersion(cardsRef, self.requestId, other.document); version != 0 {
		t.Fatalf("%s: the request's CUT lists a card first found after its check failed at %d", check, version)
	}
	if check == testBegunSuperseded {
		if version := self.refs.ListedVersion(cardsRef, self.laterId, other.document); version != 1 {
			t.Fatalf("%s: the later request lists the card first found after the check failed at %d", check, version)
		}
	} else if readable := self.refs.Readable(cardsRef, other.document); len(readable) == 0 {
		t.Fatalf("%s: a rewrite took a document no CUT lists", check)
	}
}

// The cards ref's rewrite waits on the eraser's allowance at the request's first pass, which cuts both refs and erases
// the repo's announce entry, so the slots holding the repo's and the run's documents on the cards ref keep them under
// their live keys; then the check fails, and the card's writer writes the run private. The next pass runs the rewrite
// the ledger owes, the slots rewritten under fresh keys, and rewrites no card: the card, met before the check failed,
// stays owed its CLOSURE (UnclosedPaths) and its earlier version keeps its key, so nothing says complete; where a later
// request superseded it, that request's own CLOSURE takes the card under its id. Before QD-1167 the pass skipped the
// request, and the slots kept the documents under their live keys.
func TestDirectoryFormat2RewriteOwedFinishesOnceTheErasedRequestsCheckFails(t *testing.T) {
	cardsRef := sidecar.DirectoryErasureTestCardsRef
	for _, check := range testBegunChecks() {
		seed := newTestBegunSeed(t)
		refs := seed.refs
		refs.RefuseNextClosure(cardsRef)
		pass := seed.admin.pass(t, seed.runner)
		files := pass.Files[seed.requestId]
		if len(pass.Erased[seed.requestId]) != 1 || files == nil || files.CutCount != 2 || !files.IndexWaiting || files.Complete ||
			!slices.Equal(files.ClosedPaths, []string{seed.repoPath}) || !slices.Equal(files.WaitingPaths, []string{seed.cardPath}) {
			t.Fatalf("%s: the first pass: erased %v, files %+v", check, pass.Erased[seed.requestId], files)
		}
		for _, document := range [][]byte{seed.repoDocument, seed.runDocument} {
			if readable := refs.Readable(cardsRef, document); len(readable) == 0 {
				t.Fatalf("%s: a rewrite took %s while it waited on the allowance", check, document)
			}
		}
		closures := len(seed.requestClosures())

		seed.failCheck(t, check)
		other := seed.otherMemberCard(t, refs)
		seed.writeRun(t, 2, true)
		pass = seed.admin.pass(t, seed.runner)
		seed.checkFailed(t, check, pass)
		files = pass.Files[seed.requestId]
		if files == nil || files.CutCount != 0 || files.IndexPairCount == 0 || files.IndexWaiting || files.Complete || len(files.ClosedPaths) != 0 ||
			len(files.WaitingPaths) != 0 || !slices.Equal(files.UnclosedPaths, []string{seed.cardPath}) {
			t.Fatalf("%s: the pass after the check failed: %+v", check, files)
		}
		for _, document := range [][]byte{seed.repoDocument, seed.runDocument} {
			if readable := refs.Readable(cardsRef, document); len(readable) != 0 {
				t.Fatalf("%s: index versions holding %s still open: %v", check, document, readable)
			}
		}
		if readable := refs.Readable(cardsRef, []byte("a/another")); len(readable) == 0 {
			t.Fatalf("%s: the other document left the cards ref's index", check)
		}
		if after := len(seed.requestClosures()); after != closures {
			t.Fatalf("%s: %d CLOSUREs of the cards ref for the request after its check failed", check, after-closures)
		}
		if check == testBegunSuperseded {
			// the later request, inside its own window, takes the card by its own CLOSURE
			if !slices.ContainsFunc(seed.evs.cardClosures(), func(closure *testErasurePush) bool {
				return closure.erasureId == seed.laterId && closure.path == seed.cardPath
			}) {
				t.Fatalf("%s: no CLOSURE of the later request took the card", check)
			}
		} else if readable := testReadableAt(t, seed.evs, testErasureProject, seed.cardPath); len(readable) == 0 {
			t.Fatalf("%s: the card met before the check failed was rewritten", check)
		}
		if _, _, complete := refs.Erases(seed.requestId); complete {
			t.Fatalf("%s: the erasure reads complete with a card it met owed its CLOSURE", check)
		}
		seed.noNewCopy(t, check, other)
		refs.Sweep()

		// nothing more is owed: a pass reads the request no further, the card still unrewritten
		if files := seed.admin.pass(t, seed.runner).Files[seed.requestId]; files != nil {
			t.Fatalf("%s: a pass with nothing owed: %+v", check, files)
		}
		if after := len(seed.requestClosures()); after != closures {
			t.Fatalf("%s: %d CLOSUREs of the cards ref for the request once nothing was owed", check, after-closures)
		}
		refs.Sweep()
	}
}

// The card's writer writes the run private and the pass dies between the card's CLOSURE and that CLOSURE's ERASE, so
// the card's earlier versions, naming the repo, keep their key; then the check fails. The next pass sends the ERASE the
// ledger owes, of the orphaned CLOSURE's keys by evs's state, and with nothing else owed that ERASE ends the erasure,
// which the next CUT on the cards ref drops from the set. Before QD-1167 the pass skipped the request, and the keys
// stood.
func TestDirectoryFormat2OrphanedClosureIsErasedOnceTheErasedRequestsCheckFails(t *testing.T) {
	cardsRef := sidecar.DirectoryErasureTestCardsRef
	for _, check := range testBegunChecks() {
		seed := newTestBegunSeed(t)
		refs := seed.refs
		if files := seed.admin.pass(t, seed.runner).Files[seed.requestId]; files == nil || !slices.Equal(files.WaitingPaths, []string{seed.cardPath}) {
			t.Fatalf("%s: the first pass: %+v", check, files)
		}
		seed.writeRun(t, 2, true)
		seed.evs.failEraseCount = 1
		seed.admin.mustSync(t)
		if _, err := seed.runner.Pass(t.Context()); err == nil {
			t.Fatalf("%s: the pass killed after the card's CLOSURE returned no error", check)
		}
		closures := seed.requestClosures()
		if len(closures) != 2 || closures[1].path != seed.cardPath {
			t.Fatalf("%s: the cards ref's CLOSUREs after the kill: %d", check, len(closures))
		}
		if readable := seed.evs.readable(t, testErasureProject); len(readable) == 0 {
			t.Fatalf("%s: the CLOSURE's old key went without its ERASE", check)
		}
		count, _, _ := refs.Erases(seed.requestId)

		seed.failCheck(t, check)
		other := seed.otherMemberCard(t, refs)
		pass := seed.admin.pass(t, seed.runner)
		seed.checkFailed(t, check, pass)
		files := pass.Files[seed.requestId]
		if files == nil || files.ErasedKeyCount == 0 || !files.Complete || files.CutCount != 0 || len(files.ClosedPaths) != 0 ||
			len(files.WaitingPaths) != 0 || len(files.UnclosedPaths) != 0 {
			t.Fatalf("%s: the pass after the check failed: %+v", check, files)
		}
		if readable := seed.evs.readable(t, testErasureProject); len(readable) != 0 {
			t.Fatalf("%s: card versions naming the repo still open: %v", check, readable)
		}
		if after := len(seed.requestClosures()); after != len(closures) {
			t.Fatalf("%s: %d CLOSUREs of the cards ref for the request after its check failed", check, after-len(closures))
		}
		if after, _, complete := refs.Erases(seed.requestId); after != count+1 || !complete {
			t.Fatalf("%s: after the check failed, %d ERASEs more, complete %t", check, after-count, complete)
		}
		seed.noNewCopy(t, check, other)
		refs.Sweep()
		if check != testBegunSuperseded {
			// the next CUT on the cards ref, another directory admin's, drops the ended erasure from the set; a
			// superseding request's CUT of this pass already took that place
			seed.otherAdminCut(t, cardsRef)
		}
		if refs.Lists(cardsRef, seed.requestId) {
			t.Fatalf("%s: the cards ref's set lists the erasure after it ended", check)
		}
		refs.Sweep()
		if files := seed.admin.pass(t, seed.runner).Files[seed.requestId]; files != nil {
			t.Fatalf("%s: a pass after the erasure ended: %+v", check, files)
		}
	}
}

// The request's first pass erases the repo's announce entry, and its CUT on the cards ref meets a full erasure set, so
// nothing of either ref is listed and the call waits, its documents journaled owed a CUT; then the check fails. The
// next pass, with room in the set, CUTs them on both refs as the ledger owes and rewrites the index files holding
// them, rewriting no card and no repo file for the request, and says nothing complete while the card waits for its
// writer. Before QD-1167 the pass skipped the request: its documents stayed unlisted in index files under live keys,
// in search though their announce entry was erased.
func TestDirectoryFormat2CutsOwedAreSentOnceTheErasedRequestsCheckFails(t *testing.T) {
	cardsRef := sidecar.DirectoryErasureTestCardsRef
	streamsRef := sidecar.DirectoryErasureTestStreamsRef
	for _, check := range testBegunChecks() {
		seed := newTestBegunSeed(t)
		refs := seed.refs
		seed.hooks.refuseCut[cardsRef] = sidecar.ErrIndexErasureSetFull
		pass := seed.admin.pass(t, seed.runner)
		files := pass.Files[seed.requestId]
		if len(pass.Erased[seed.requestId]) != 1 || files == nil || files.CutCount != 0 || !files.IndexWaiting || files.Complete {
			t.Fatalf("%s: the pass whose CUT the full set refused: erased %v, files %+v", check, pass.Erased[seed.requestId], files)
		}
		for _, ref := range []string{cardsRef, streamsRef} {
			if refs.Lists(ref, seed.requestId) {
				t.Fatalf("%s: %s lists the erasure before its CUT", check, ref)
			}
		}

		seed.failCheck(t, check)
		other := seed.otherMemberCard(t, refs)
		pass = seed.admin.pass(t, seed.runner)
		seed.checkFailed(t, check, pass)
		files = pass.Files[seed.requestId]
		if files == nil || files.CutCount != 2 || files.IndexPairCount == 0 || files.IndexWaiting || files.Complete || len(files.ClosedPaths) != 0 ||
			!slices.Equal(files.WaitingPaths, []string{seed.cardPath}) {
			t.Fatalf("%s: the pass after the check failed: %+v", check, files)
		}
		for _, each := range []struct {
			ref      string
			document []byte
			version  uint64
		}{
			{ref: cardsRef, document: seed.repoDocument, version: 2},
			{ref: cardsRef, document: seed.runDocument, version: 1},
			{ref: streamsRef, document: seed.repoDocument, version: 1},
		} {
			if version := refs.ListedVersion(each.ref, seed.requestId, each.document); version != each.version {
				t.Fatalf("%s: %s lists %s at %d", check, each.ref, each.document, version)
			}
			if readable := refs.Readable(each.ref, each.document); len(readable) != 0 {
				t.Fatalf("%s: on %s index versions holding %s still open: %v", check, each.ref, each.document, readable)
			}
		}
		if closures := seed.requestClosures(); len(closures) != 0 {
			t.Fatalf("%s: %d CLOSUREs of the cards ref for the request", check, len(closures))
		}
		if _, _, complete := refs.Erases(seed.requestId); complete {
			t.Fatalf("%s: the erasure reads complete while the card waits for its writer", check)
		}
		seed.noNewCopy(t, check, other)
		refs.Sweep()
		if files := seed.admin.pass(t, seed.runner).Files[seed.requestId]; files != nil {
			t.Fatalf("%s: a pass with nothing owed: %+v", check, files)
		}
		refs.Sweep()
	}
}
