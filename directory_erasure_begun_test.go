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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"testing"
	"time"

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
		// pushed after the request, so every pass reaches the older request first
		world.clock.Advance(time.Minute)
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
// the ledger owes, the slots rewritten under fresh keys, and rewrites the card, met before the check failed, by
// CLOSURE, whose ERASE ends the erasure (QD-1168), so the next CUT on the cards ref drops it from the set, a
// superseding request's own CUT in the same pass among them. Before QD-1167 the pass skipped the request, and the slots
// kept the documents under their live keys; before QD-1168 the card stayed owed its CLOSURE, its earlier version
// keeping its key, and the erasure stayed open.
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
		if files == nil || files.CutCount != 0 || files.IndexPairCount == 0 || files.IndexWaiting || !files.Complete ||
			!slices.Equal(files.ClosedPaths, []string{seed.cardPath}) || len(files.WaitingPaths) != 0 {
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
		if after := seed.requestClosures(); len(after) != closures+1 || after[len(after)-1].path != seed.cardPath {
			t.Fatalf("%s: %d CLOSUREs of the cards ref for the request after its check failed", check, len(after)-closures)
		}
		if readable := seed.evs.readable(t, testErasureProject); len(readable) != 0 {
			t.Fatalf("%s: card versions naming the repo still open: %v", check, readable)
		}
		if _, _, complete := refs.Erases(seed.requestId); !complete {
			t.Fatalf("%s: the erasure reads open after the card's ERASE", check)
		}
		seed.noNewCopy(t, check, other)
		refs.Sweep()
		if check != testBegunSuperseded {
			// a superseding request's CUT of this pass already took this place
			seed.otherAdminCut(t, cardsRef)
		}
		if refs.Lists(cardsRef, seed.requestId) {
			t.Fatalf("%s: the cards ref's set lists the erasure after it ended", check)
		}
		refs.Sweep()

		// nothing more is owed: a pass reads the request no further
		if files := seed.admin.pass(t, seed.runner).Files[seed.requestId]; files != nil {
			t.Fatalf("%s: a pass with nothing owed: %+v", check, files)
		}
		if after := len(seed.requestClosures()); after != closures+1 {
			t.Fatalf("%s: %d CLOSUREs of the cards ref for the request once it ended", check, after-closures)
		}
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
			len(files.WaitingPaths) != 0 {
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
// nothing of either ref is listed and the call waits, its documents journaled owed a CUT, before any file's CLOSURE;
// then the check fails. The next pass, with room in the set, CUTs them on both refs as the ledger owes and rewrites the
// index files holding them, and the repo file, met at the first pass, by CLOSURE where its standing version, the
// request's marker or a later request's, no longer holds the repo's document (QD-1168), not where the repo was
// announced again; it says nothing complete while the card waits for its writer. Before QD-1167 the pass skipped the
// request: its documents stayed unlisted in index files under live keys, in search though their announce entry was
// erased.
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
		closed := []string{seed.repoPath}
		if check == testBegunLapsed {
			// the repo file holds the repo's item announced again
			closed = []string{}
		}
		if files == nil || files.CutCount != 2 || files.IndexPairCount == 0 || files.IndexWaiting || files.Complete ||
			!slices.Equal(files.ClosedPaths, closed) || !slices.Equal(files.WaitingPaths, []string{seed.cardPath}) {
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
		closures := seed.requestClosures()
		if len(closures) != len(closed) || slices.ContainsFunc(closures, func(closure *testErasurePush) bool { return closure.path != seed.repoPath }) {
			t.Fatalf("%s: %d CLOSUREs of the cards ref for the request", check, len(closures))
		}
		if check != testBegunLapsed {
			if readable := seed.evs.readable(t, testErasureRepoTitle); len(readable) != 0 {
				t.Fatalf("%s: repo file versions holding the title still open: %v", check, readable)
			}
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

// The card waits for its writer when a later request supersedes the request, and the writer then writes the run
// private. Another directory admin's device, which holds no ledger of the request, works the later request first, its
// CLOSURE taking the card under the later request's id. The request's next pass reads every path its ledger met
// rewritten, the repo file and the card both by the later request's CLOSUREs, with nothing else owed, and ends the
// erasure by a rewrite of the cards ref (QD-1168): its last ERASE there says complete, a completion ERASE where nothing
// is left to rewrite (QD-1132's form); the later request's rewrite left the index file it rewrote with an earlier version
// under a key that ERASE destroyed, which the rewrite reads as holding, so it rewrites that file once more. No CLOSURE of
// the cards ref is the request's own, and the next CUT on the cards ref drops it from the set. Before QD-1168 nothing
// of the request was owed then, so no ERASE of it said complete and it stayed pending in the set for good.
func TestDirectoryFormat2SupersededErasureWhoseCardALaterRequestRewroteFirstEnds(t *testing.T) {
	cardsRef := sidecar.DirectoryErasureTestCardsRef
	seed := newTestBegunSeed(t)
	refs := seed.refs
	if files := seed.admin.pass(t, seed.runner).Files[seed.requestId]; files == nil || files.Complete ||
		!slices.Equal(files.ClosedPaths, []string{seed.repoPath}) || !slices.Equal(files.WaitingPaths, []string{seed.cardPath}) {
		t.Fatalf("the first pass: %+v", files)
	}
	seed.failCheck(t, testBegunSuperseded)
	seed.writeRun(t, 2, true)

	other := seed.evs.adminDevice(t)
	refs.Admit(other.writer.sidecarId)
	otherRunner := testRefsRunner(t, other, seed.evs.bindRefs(other, refs))
	otherPass := other.pass(t, otherRunner)
	if files := otherPass.Files[seed.laterId]; files == nil || !files.Complete || !slices.Contains(files.ClosedPaths, seed.cardPath) {
		t.Fatalf("the other device's pass of the later request: %+v", files)
	}
	if files := otherPass.Files[seed.requestId]; files != nil {
		t.Fatalf("the other device worked the request with no ledger of it: %+v", files)
	}
	if readable := seed.evs.readable(t, testErasureProject); len(readable) != 0 {
		t.Fatalf("card versions naming the repo still open: %v", readable)
	}
	count, _, complete := refs.Erases(seed.requestId)
	if complete {
		t.Fatal("the request's erasure reads complete before its pass")
	}
	closures := len(seed.requestClosures())

	pass := seed.admin.pass(t, seed.runner)
	seed.checkFailed(t, testBegunSuperseded, pass)
	files := pass.Files[seed.requestId]
	if files == nil || !files.Complete || len(files.ClosedPaths) != 0 || files.CutCount != 0 || files.ErasedKeyCount != 0 ||
		len(files.WaitingPaths) != 0 || len(files.ConflictPaths) != 0 {
		t.Fatalf("the pass once the later request rewrote every path the request met: %+v", files)
	}
	ended, _, complete := refs.Erases(seed.requestId)
	if ended <= count || !complete {
		t.Fatalf("the request's ERASEs: %d more, complete %t", ended-count, complete)
	}
	if after := len(seed.requestClosures()); after != closures {
		t.Fatalf("%d CLOSUREs of the cards ref for the request", after-closures)
	}
	refs.Sweep()
	seed.otherAdminCut(t, cardsRef)
	if refs.Lists(cardsRef, seed.requestId) {
		t.Fatal("the cards ref's set lists the erasure after it ended")
	}
	refs.Sweep()
	if files := seed.admin.pass(t, seed.runner).Files[seed.requestId]; files != nil {
		t.Fatalf("a pass after the erasure ended: %+v", files)
	}
	if after, _, _ := refs.Erases(seed.requestId); after != ended {
		t.Fatalf("%d ERASEs of the request after it ended", after-ended)
	}
}

// Two directory admins' runners work the request, and its card waits for its writer on both copies; then the check
// fails, its repo announced again, and the writer writes the run private. One runner rewrites the card, which it met, by
// CLOSURE, and that CLOSURE's ERASE ends the erasure. The other then reads the card rewritten, by that runner's
// CLOSURE, with nothing else owed and no ERASE of its own having said complete, so it asks the cards ref's rewrite to
// end the erasure; that rewrite reads it complete with nothing left to rewrite there and sends nothing (hooked, as the
// eraser answers then: its history walk here reads more conservatively, rewriting once more what another runner's
// CLOSURE replaced). The runner keeps that reading, so no later pass asks again (QD-1168).
func TestDirectoryFormat2ErasureAnotherRunnerEndedIsReadEnded(t *testing.T) {
	cardsRef := sidecar.DirectoryErasureTestCardsRef
	seed := newTestBegunSeed(t)
	refs := seed.refs
	second := seed.evs.adminDevice(t)
	refs.Admit(second.writer.sidecarId)
	secondRunner := testRefsRunner(t, second, seed.evs.bindRefs(second, refs))
	for _, each := range []struct {
		device *testDirectoryDevice
		runner *sidecar.DirectoryErasureRunner
	}{
		{device: seed.admin, runner: seed.runner},
		{device: second, runner: secondRunner},
	} {
		if files := each.device.pass(t, each.runner).Files[seed.requestId]; files == nil || files.Complete || !slices.Equal(files.WaitingPaths, []string{seed.cardPath}) {
			t.Fatalf("a runner's first pass: %+v", files)
		}
	}
	seed.failCheck(t, testBegunLapsed)
	seed.writeRun(t, 2, true)
	files := second.pass(t, secondRunner).Files[seed.requestId]
	if files == nil || !files.Complete || !slices.Equal(files.ClosedPaths, []string{seed.cardPath}) {
		t.Fatalf("the second runner's pass: %+v", files)
	}
	count, _, complete := refs.Erases(seed.requestId)
	if !complete {
		t.Fatal("the erasure reads open after the second runner's CLOSURE")
	}
	closures := len(seed.requestClosures())

	seed.hooks.readDone[cardsRef] = true
	pass := seed.admin.pass(t, seed.runner)
	seed.checkFailed(t, testBegunLapsed, pass)
	files = pass.Files[seed.requestId]
	if seed.hooks.readDoneCount != 1 || files == nil || files.Complete || files.CutCount != 0 || files.IndexPairCount != 0 || files.ErasedKeyCount != 0 ||
		len(files.ClosedPaths) != 0 || len(files.WaitingPaths) != 0 || len(files.ConflictPaths) != 0 {
		t.Fatalf("the first runner's pass once the second ended the erasure: %d rewrites read it ended, files %+v", seed.hooks.readDoneCount, files)
	}
	for range 2 {
		if files := seed.admin.pass(t, seed.runner).Files[seed.requestId]; files != nil {
			t.Fatalf("a later pass of the first runner: %+v", files)
		}
	}
	if after, _, complete := refs.Erases(seed.requestId); after != count || !complete {
		t.Fatalf("the first runner's passes: %d ERASEs more, complete %t", after-count, complete)
	}
	if after := len(seed.requestClosures()); after != closures || seed.hooks.readDoneCount != 1 {
		t.Fatalf("%d CLOSUREs of the cards ref, %d rewrites, after the erasure ended", after-closures, seed.hooks.readDoneCount)
	}
	refs.Sweep()
}

// Whether the copy holds the request's erasure_request entry.
func (self *testBegunSeed) holds(device *testDirectoryDevice) bool {
	return slices.ContainsFunc(device.client.ErasureRequests(), func(request *sidecar.DirectoryErasureRequestView) bool {
		return request.RequestId == self.requestId
	})
}

// A compromise revocation of the request's signer, from the request's own push on, voids its signature while the card
// waits for its writer, and the directory admin's device restarts: its reader, reading the log again, refuses the
// request's entry, so the copy no longer holds the request, though the ERASEs naming it stand. The card's writer then
// writes the run private, and the restarted device's pass works the request's ledger row all the same, by the repo and
// marker version the row kept: it rewrites the card by CLOSURE and that CLOSURE's ERASE ends the erasure (QD-1169).
// Before, a pass walked only the requests the copy holds, and the erasure stayed open for good.
func TestDirectoryFormat2ErasureWhoseRequestARestartedReaderRefusedFinishes(t *testing.T) {
	seed := newTestBegunSeed(t)
	refs := seed.refs
	if files := seed.admin.pass(t, seed.runner).Files[seed.requestId]; files == nil || files.Complete || !slices.Equal(files.WaitingPaths, []string{seed.cardPath}) {
		t.Fatalf("the first pass: %+v", files)
	}
	seed.failCheck(t, testBegunVoided)
	restarted := seed.world.restarted(seed.admin)
	restartedRunner := testRefsRunner(t, restarted, seed.evs.bindRefs(restarted, refs))
	pass := restarted.pass(t, restartedRunner)
	if seed.holds(restarted) {
		t.Fatal("the restarted copy holds the request whose signature a compromise revocation voided")
	}
	if files := pass.Files[seed.requestId]; files != nil || !slices.Equal(pass.Waiting, []sidecar.Id{seed.requestId}) {
		t.Fatalf("the restarted device's pass with the card waiting: waiting %v, files %+v", pass.Waiting, files)
	}
	other := seed.otherMemberCard(t, refs)
	other.writeRun(t, 2, true)

	seed.writeRun(t, 2, true)
	pass = restarted.pass(t, restartedRunner)
	files := pass.Files[seed.requestId]
	if len(pass.Erased) != 0 || files == nil || !files.Complete || !slices.Equal(files.ClosedPaths, []string{seed.cardPath}) || files.CutCount != 0 ||
		len(files.WaitingPaths) != 0 {
		t.Fatalf("the restarted device's pass after the card's writer wrote it private: erased %v, files %+v", pass.Erased, files)
	}
	if readable := seed.evs.readable(t, testErasureProject); len(readable) != 0 {
		t.Fatalf("card versions naming the repo still open: %v", readable)
	}
	if readable := testReadableAt(t, seed.evs, testWindowOtherProject, other.cardPath); len(readable) == 0 {
		t.Fatal("a card first met after the request left the copy lost its key")
	}
	if version := refs.ListedVersion(sidecar.DirectoryErasureTestCardsRef, seed.requestId, other.document); version != 0 {
		t.Fatalf("a card first met after the request left the copy is cut at %d", version)
	}
	if _, _, complete := refs.Erases(seed.requestId); !complete {
		t.Fatal("the erasure reads open after the card's ERASE")
	}
	refs.Sweep()
	if files := restarted.pass(t, restartedRunner).Files[seed.requestId]; files != nil {
		t.Fatalf("a pass after the erasure ended: %+v", files)
	}
}

// The request's card waits for its writer past the sweep window, and past the request's 400 days the runner's own
// retention expiry takes its erasure_request entry, so the copy no longer holds the request. The card's writer then
// writes the run private, and the pass works the request's ledger row all the same, by the repo and marker version the
// row kept: it rewrites the card by CLOSURE and that CLOSURE's ERASE ends the erasure (QD-1169). The row, first worked
// past the ledger's 60-day hold ago, is not forgotten in the middle of the call that ends it, so no later pass makes it
// again as newly begun and rewrites anything more. Before, the expired request was read no more and the erasure
// stayed open for good.
func TestDirectoryFormat2ErasureWhoseRequestEntryExpiredFinishes(t *testing.T) {
	seed, admin, refs, erase := newTestErasureRefsSeed(t)
	revocation := seed.revoke(t)
	requestId := revocation.RequestId
	cardPath := sidecar.DirectoryCardPath(seed.daemon.writer.sidecarId)
	runner, err := sidecar.NewDirectoryErasureRunner(&sidecar.DirectoryErasureRunnerArgs{
		Client: admin.client, Erase: erase, Raise: (&testErasureRaises{}).raise, Random: &testErasureDelay{},
		Expire: func(ctx context.Context, directoryId sidecar.Id, hold func(entry *sidecar.RecordReadEntry) bool) error {
			_, err := admin.record.Retention().Expire(ctx, &sidecar.RecordRetentionExpireArgs{LogId: directoryId, Hold: hold})
			return err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if files := admin.pass(t, runner).Files[requestId]; files == nil || files.Complete || !slices.Equal(files.WaitingPaths, []string{cardPath}) {
		t.Fatalf("the first pass: %+v", files)
	}
	retention := sidecar.DefaultRecordRetentionSettings()
	keep := time.Duration(retention.DirectoryKeepDays) * retention.Day
	testAgeRequest(t, seed.world, admin, requestId, keep+time.Hour)
	admin.pass(t, runner)
	admin.pass(t, runner)
	if slices.ContainsFunc(admin.client.ErasureRequests(), func(request *sidecar.DirectoryErasureRequestView) bool { return request.RequestId == requestId }) {
		t.Fatal("the copy holds the request past its keep_days")
	}

	seed.writeRun(t, 2, true)
	pass := admin.pass(t, runner)
	files := pass.Files[requestId]
	if len(pass.Erased) != 0 || files == nil || !files.Complete || !slices.Equal(files.ClosedPaths, []string{cardPath}) || files.CutCount != 0 ||
		len(files.WaitingPaths) != 0 {
		t.Fatalf("the pass after the card's writer wrote it private: erased %v, files %+v", pass.Erased, files)
	}
	if readable := seed.evs.readable(t, testErasureProject); len(readable) != 0 {
		t.Fatalf("card versions naming the repo still open: %v", readable)
	}
	if _, _, complete := refs.Erases(requestId); !complete {
		t.Fatal("the erasure reads open after the card's ERASE")
	}
	refs.Sweep()
	ended, _, _ := refs.Erases(requestId)
	for range 2 {
		if files := admin.pass(t, runner).Files[requestId]; files != nil {
			t.Fatalf("a pass after the erasure ended: %+v", files)
		}
	}
	if after, _, _ := refs.Erases(requestId); after != ended {
		t.Fatalf("%d ERASEs of the request after it ended", after-ended)
	}
}

// Takes the repo and marker version out of every row of the ledger a device keeps, as a row written before they were
// kept reads.
func testErasureLedgerWithoutRepos(t *testing.T, device *testDirectoryDevice) {
	t.Helper()
	reader, err := device.store.Open("erasure_files")
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	document := map[string]any{}
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatal(err)
	}
	erasures, _ := document["erasures"].(map[string]any)
	if len(erasures) == 0 {
		t.Fatal("the ledger keeps no erasure")
	}
	for _, row := range erasures {
		if _, ok := row.(map[string]any)["repo_id"]; !ok {
			t.Fatal("a row of the ledger kept no repo")
		}
		delete(row.(map[string]any), "repo_id")
		delete(row.(map[string]any), "marker_version")
	}
	content, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := device.store.Create("erasure_files")
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
}

// A row written before the ledger kept a request's repo and marker version, of a request a restarted reader refused
// after a compromise revocation of its signer: where the row owes a rewrite and no path it met is owed a CLOSURE, the
// pass works it from the ledger alone, reading no file, and the cards ref's rewrite that waited on the allowance runs
// and ends the erasure; where the card it met still waits for its writer, which only a read of the sync's files could
// judge, the row is left as it is and nothing is sent (QD-1169).
func TestDirectoryFormat2ErasureRowWithNoRepoIsWorkedFromTheLedgerAlone(t *testing.T) {
	cardsRef := sidecar.DirectoryErasureTestCardsRef
	for _, waiting := range []bool{false, true} {
		seed := newTestBegunSeed(t)
		refs := seed.refs
		if !waiting {
			// the card goes at the first pass, while the cards ref's rewrite waits on the allowance
			seed.writeRun(t, 2, true)
			refs.RefuseNextClosure(cardsRef)
		}
		files := seed.admin.pass(t, seed.runner).Files[seed.requestId]
		if files == nil || files.Complete || files.IndexWaiting == waiting || slices.Equal(files.WaitingPaths, []string{seed.cardPath}) != waiting {
			t.Fatalf("waiting %t: the first pass: %+v", waiting, files)
		}
		seed.failCheck(t, testBegunVoided)
		testErasureLedgerWithoutRepos(t, seed.admin)
		restarted := seed.world.restarted(seed.admin)
		restartedRunner := testRefsRunner(t, restarted, seed.evs.bindRefs(restarted, refs))
		count, _, _ := refs.Erases(seed.requestId)

		pass := restarted.pass(t, restartedRunner)
		if seed.holds(restarted) {
			t.Fatalf("waiting %t: the restarted copy holds the request", waiting)
		}
		files = pass.Files[seed.requestId]
		after, _, complete := refs.Erases(seed.requestId)
		switch {
		case waiting:
			if files != nil || len(pass.Waiting) != 0 || after != count || complete {
				t.Fatalf("waiting %t: the pass of a row that cannot judge its card: waiting %v, files %+v, %d ERASEs more", waiting, pass.Waiting, files, after-count)
			}
			if readable := testReadableAt(t, seed.evs, testErasureProject, seed.cardPath); len(readable) == 0 {
				t.Fatalf("waiting %t: the waiting card lost its key", waiting)
			}
		default:
			if files == nil || !files.Complete || files.IndexPairCount == 0 || files.CutCount != 0 || len(files.ClosedPaths) != 0 || len(files.WaitingPaths) != 0 || !complete {
				t.Fatalf("waiting %t: the pass from the ledger alone: files %+v, complete %t", waiting, files, complete)
			}
			for _, document := range [][]byte{seed.repoDocument, seed.runDocument} {
				if readable := refs.Readable(cardsRef, document); len(readable) != 0 {
					t.Fatalf("waiting %t: index versions holding %s still open: %v", waiting, document, readable)
				}
			}
		}
		refs.Sweep()
	}
}
